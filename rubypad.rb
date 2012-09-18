#!/usr/bin/env ruby

# rubypad.rb
#
# manages a database of secrets using one-time pad encryption

require 'etc'
require 'sqlite3'

# Set location of database file.
$db_file = Etc.getpwuid.dir + '/.secrets'

# Connect to database. Show results as a hash for clarity.
$db = SQLite3::Database.new($db_file)
$db.results_as_hash = true

#                     #
# Database functions. #
#                     #

# Check to see if the secrets table exists.
def table_exists?
    results = $db.execute %q{
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = 'secrets'
    }

    return results.length > 0
end

# Create the secrets table.
def create_table
    $db.execute %q{
        CREATE TABLE secrets (
		id integer primary key,
        secret varchar(1024),
        hint varchar(1024))
    }
end

# Add a secret to the database. Return the ID of the new database row.
def add_to_db(secret, hint)
    $db.execute("INSERT INTO secrets (secret, hint) VALUES (?, ?)",
                secret, hint)

    # Handy function to get ID of last row inserted.
    $db.last_insert_row_id
end

# Search the database with the given query.
def search_db(query)
    query = '%' + query + '%'

    $db.execute(%q{
        SELECT id, hint
        FROM secrets
        WHERE id LIKE ? OR hint LIKE ?
    }, query, query)
end

def delete_from_db(id)
    puts $db.execute(%q{
        DELETE FROM secrets
        WHERE id = ?
    }, id)
end

#                    #
# Utility functions. #
#                    #

# Convert a number to its letter representation.
def ntol(n)
    alphabet = ('a'..'z').to_a
    alphabet[n]
end

# Convert a letter to its number representation.
def lton(l)
    alphabet = ('a'..'z').to_a
    alphabet.index(l)
end

# Downcase a string, then remove spaces, punctuation, numbers, symbols, etc.,
# from the string.
def clean(text)
    text.downcase.gsub(/[^a-z]/, '')
end

# Make a pad of random letters of length len.
def make_pad(len)
    padtext = ''

    len.times do
        padtext += ntol(rand(26))
    end

    return padtext
end

# Pad text with the given padtext and return the ciphertext.
def encrypt(text, padtext)
    ciphertext = ''

    text.length.times do |idx|
        # You have to do [idx,1] in ruby 1.8; in later version(s), you can just 
        # do [idx]. Oh well.
        lnum = lton(text[idx,1])
        pnum = lton(padtext[idx,1])
        cnum = (lnum + pnum) % 26

        ciphertext += ntol(cnum)
    end

    return ciphertext
end

# Decrypt the ciphertext given the pad.
def decrypt(ciphertext, padtext)
    text = ''

    ciphertext.length.times do |idx|
        # You have to do [idx,1] in ruby 1.8; in later version(s), you can just 
        # do [idx]. Oh well.
        cnum = lton(ciphertext[idx,1])
        pnum = lton(padtext[idx,1])
        lnum = (cnum - pnum) % 26

        text += ntol(lnum)
    end

    return text
end

#                 #
# Menu functions. #
#                 #

# Display the add menu/prompt.
def add
    print "Enter a secret (\"secret # hint words\"): "
    secret, hint = gets.chomp.split(' # ')

    secret = clean(secret)
    padtext = make_pad(secret.length)
    ciphertext = encrypt(secret, padtext)

    id = add_to_db(ciphertext, hint)

    puts "Added secret #{id} with pad \"#{padtext}\""
end

# List secrets in the database.
def list
    results = $db.execute("SELECT id, hint FROM secrets")
    
    puts "Secrets database contains #{results.length} row(s)."
    
    results.each do |row|
        puts "    #{row['id']}: #{row['hint']}"
    end
end

# Display the decode menu/prompt.
def decode
    # Ask for ID.
    print "Enter ID of secret to decode: "
    id = gets.chomp
    
    # Get corresponding secret; abort if it doesn't exist.
    result = $db.execute("SELECT secret FROM secrets WHERE id = ?", id)[0]
    if result == nil
        puts "Specified secret does not exist."
        return
    end

    ciphertext = result['secret']

    # Ask for pad.
    print "Enter pad: "
    padtext = gets.chomp

    # Decrypt.
    text = decrypt(ciphertext, padtext)

    # Print result.
    puts "Decoded text:"
    puts "    #{text}"
end

# Display the search menu/prompt.
def search
    print "Enter query: "
    query = gets.chomp

    results = search_db(query)

    puts "#{results.length} row(s) found."

    results.each do |row|
        puts "    #{row['id']}: #{row['hint']}"
    end
end

# Display the delete menu/prompt.
def delete
    print "Enter ID of record to delete: "
    id = gets.chomp
    delete_from_db(id)
end

# Main (menu) loop.
loop do
    if !table_exists?
        puts "Creating secrets table..."
        create_table
    end

    print %q{
rubypad
    1. SEARCH for secrets
    2. LIST all secrets
    3. DECODE a secret
    4. ADD a secret
    5. DELETE a secret
    6. QUIT

    ? }

    choice = gets.chomp
    puts
    
    case choice
		when '1'
            search
		when '2'
            list
		when '3'
            decode
		when '4'
            add
		when '5'
            delete
        when '6'
            exit
	end
end
