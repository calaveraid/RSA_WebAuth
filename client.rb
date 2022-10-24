require 'openssl'
require 'http'

#config
DATADIR = './data/'
SERVER_URL = 'http://127.0.0.1:4567'

def createProfile username
    if Dir.exists? DATADIR+username
        puts "Alias [#{username}] is already used."
        return nil
    end
    
    privateKey = OpenSSL::PKey::RSA.new(2048)
    Dir.mkdir DATADIR+username
    File.open "#{DATADIR+username}/private.pem", 'wb' do |f|
        f.write privateKey.export
    end
    File.open "#{DATADIR+username}/public.pem", 'wb' do |f|
        f.write privateKey.public_key.export
    end

    return privateKey
end


def loginUser username, privateKey
    puts "Login user #{username}..."
    response = HTTP.post(SERVER_URL+'/login', form: {id: username})

    if response.code == 202
        secret = response.body.to_s
        puts "Decrypting response..."
        decrypted = privateKey.private_decrypt secret, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING rescue 'KEY_ERROR'
        puts "Decrypted: #{decrypted}\n"
        session_cookie = response.cookies.cookies
        response = HTTP.cookies(session_cookie).post(SERVER_URL+'/login', form: {id: username, decrypted: decrypted})
    end

    return response.body.to_s, response.code
end


def registerUser username, publicKey
    puts "Registering user #{username}...\n"
    response = HTTP.post(SERVER_URL+'/register', form: {id: username, public_key: publicKey.export})
    return response.body.to_s, response.code
end


if __FILE__ == $0
    if not Dir.exists? DATADIR
        Dir.mkdir DATADIR
    end

    users = Hash.new

    Dir.entries(DATADIR).each do |item|
        if File.exists? "#{DATADIR+item}/private.pem"
            users[item] = OpenSSL::PKey::RSA.new File.read "#{DATADIR+item}/private.pem"
        end
    end 

    begin
        puts 'Identykee Client (TESTING)'
        puts '=========================='
        puts 'Registered users:'
        users.keys.each do |u|
            puts " - #{u}"
        end
        puts
        puts 'Enter a existing user for login or new name to register: '
        username = gets.chomp
        if users.has_key? username
            puts loginUser username, users[username]
        else
            users[username] = createProfile username
            puts registerUser username, users[username].public_key
        end
        puts
    rescue Interrupt => e
        puts "\nTerminated by user."
    end
end