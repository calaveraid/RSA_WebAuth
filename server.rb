require 'sinatra'
require 'openssl' 

#utils
def random_string size
    charset = Array('A'..'Z') + Array('a'..'z') + Array('1'..'0')
    Array.new(size) { charset.sample }.join
end

#config
DATADIR = './server_data/'
if not Dir.exists? DATADIR
    Dir.mkdir DATADIR
end

enable :sessions
disable :show_exceptions

post '/register' do
    @username = params[:id]
    @publicKey = params[:public_key]
    if Dir.entries(DATADIR).include? @username
        status 400
        response = "Username [#{@username}] already exists."
    else
        File.open DATADIR+@username, 'wb' do |f|
            f.write @publicKey
        end
        status 200
        response = "User [#{@username}] created."
    end
    response
end


post '/login' do
    @username = params[:id]
    if params[:decrypted] != nil
        if session[:secret] == params[:decrypted]
            status 200
            response = "Access granted: #{@username}"
        else
            status 400
            response = "Key authentication error: #{@username}"
        end
    elsif Dir.entries(DATADIR).include? @username
        @publicKey = OpenSSL::PKey::RSA.new File.read DATADIR+@username
        secret = random_string 32
        session[:secret] = secret
        status 202
        response = @publicKey.public_encrypt secret, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
    else
        status 400
        response = "Wrong User: #{@username}"
    end
    response
end