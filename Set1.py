from crypto_commons import generic
from base64 import b64encode

#Challenge 1
#Convert hex to base64

def hex2Base64(input_data):
    clearText = ''.join([chr(int(x, 16)) for x in generic.chunk(input_data, 2)])
    return b64encode(clearText)

#Challenge 2
#Xor 2 hex strings

def xorHex(hex_a, hex_b):
    chunks_a = [int(x, 16) for x in generic.chunk(hex_a, 2)]
    chunks_b = [int(x, 16) for x in generic.chunk(hex_b, 2)]

    return ''.join(hex(x)[2:].zfill(2) for x in generic.xor(chunks_a, chunks_b))

#Challenge 3
#Brute one xor character

def scorePlaintext(input_data):
    letter_frequencies = {'a':7.52766,'e':7.0925,'o':5.17,'r':4.96032,'i':4.69732,'s':4.61079,'n':4.56899,'1':4.35053,'t':3.87388,'l':3.77728,'2':3.12312,'m':2.99913,'d':2.76401,'0':2.74381,'c':2.57276,'p':2.45578,'3':2.43339,'h':2.41319,'b':2.29145,'u':2.10191,'k':1.96828,'4':1.94265,'5':1.88577,'g':1.85331,'9':1.79558,'6':1.75647,'8':1.66225,'7':1.621,'y':1.52483,'f':1.2476,'w':1.24492,'j':0.836677,'v':0.833626,'z':0.632558,'x':0.573305,'q':0.346119,'A':0.130466,'S':0.108132,'E':0.0970865,'R':0.08476,'B':0.0806715,'T':0.0801223,'M':0.0782306,'L':0.0775594,'N':0.0748134,'P':0.073715,'O':0.0729217,'I':0.070908,'D':0.0698096,'C':0.0660872,'H':0.0544319,'G':0.0497332,'K':0.0460719,'F':0.0417393,'J':0.0363083,'U':0.0350268,'W':0.0320367,'.':0.0316706,'!':0.0306942,'Y':0.0255073,'*':0.0241648,'@':0.0238597,'V':0.0235546,'-':0.0197712,'Z':0.0170252,'Q':0.0147064,'X':0.0142182,'_':0.0122655,'$':0.00970255,'#':0.00854313,',':0.00323418,'/':0.00311214,'+':0.00231885,'?':0.00207476,';':0.00207476,'^':0.00195272,' ':0.00189169,'%':0.00170863,'~':0.00152556,'=':0.00140351,'&':0.00134249,'`':0.00115942,'\\':0.00115942,')':0.00115942,']':0.0010984,'[':0.0010984,':':0.000549201,'<':0.000427156,'(':0.000427156,'>':0.000183067,'"':0.000183067,'|':0.000122045,'{':0.000122045,'\'':0.000122045,'}':6.10223e-0,}

    my_frequencies = {}

    for i in input_data:
        if my_frequencies.has_key(i):
            my_frequencies[i] += 1
        elif letter_frequencies.has_key(i):
            my_frequencies[i] = 1

    score = 0
    for key in my_frequencies.keys():
        score += abs(letter_frequencies[key] - len(input_data)/my_frequencies[key])

    return score


def bruteOneCharXor(input_data):

    chunks = [int(x, 16) for x in generic.chunk(input_data, 2)]

    bestScore = 10**10
    bestGuess = ""

    for i in range(256):
        guessedPass = ''.join([chr(chunks[x] ^ i) for x in range(len(chunks))])
        if(generic.is_printable(guessedPass)):

            currentScore = scorePlaintext(guessedPass)

            if currentScore < bestScore:
                bestScore = currentScore
                bestGuess = guessedPass

    return bestGuess



#Challenge 4

def findXoredLine(input_file):

    lines = open(input_file, "r").read().split("\n")

    bestOutput = ""
    bestScore = 10**10

    for i in lines:
        currentLine = [int(x, 16) for x in generic.chunk(i, 2)]

        for xor in range(256):
            xoredLine = ''.join(chr(x ^ xor) for x in currentLine)

            if(generic.is_printable(xoredLine)):
                score = scorePlaintext(xoredLine)
                if score < bestScore:
                    bestOutput = xoredLine
                    bestScore = score

    return bestOutput


#Challenge 5
#Encrypt a string with a key

def encryptString(message):
    key = map(ord, "ICE")

    encryptedMessage = ''.join([''.join([hex(q)[2:].zfill(2) for q in generic.xor(map(ord, x), key)]) for x in generic.chunk_with_remainder(message, len(key))])

    return(encryptedMessage)




#tests
assert hex2Base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

assert xorHex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

assert bruteOneCharXor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736") == "Cooking MC's like a pound of bacon"

assert findXoredLine("Set1Challenge4Data.txt") == "Now that the party is jumping\n"

assert encryptString("""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal""") == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

