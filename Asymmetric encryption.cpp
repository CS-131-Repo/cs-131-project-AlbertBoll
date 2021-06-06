#include"Asymmetric encryption.h"

#include <iomanip>
#include <sstream>


bool Sha256::encrypt(const std::vector<uint8_t>& original_message, std::vector<uint8_t>* encrypted_digest)
{

    if(!original_message.empty() && encrypted_digest)
    {

    		//preprocessing original message 
        auto message = original_message;
        preprocessing(&message);


    		//break message into multiple chunks with each chunk 64 bytes in size 
        std::vector<std::vector<uint8_t>> chunks;
        decomposeTextInto64BytesChunks(message, &chunks);

        std::vector<uint32_t> message_digest(H);
        std::vector<uint32_t> words;

        for(auto& chunk : chunks)
        {
            constructWords(chunk, &words);
            transform(words, &message_digest);
        }

        HashValue(message_digest, encrypted_digest);

        return true;
    		
    }
	
    return false;
}

bool Sha256::preprocessing(std::vector<uint8_t>* message)
{
    if (message)
    {
    		//total size in bits
        const uint64_t original_bit_size = message->size() * 8;

        //! append filling bits
        const size_t remainder = message->size() % 64;

    		//if remainder is less than 56 bytes = 448 bits
        if (remainder < 56)
        {
        		// append 1 byte(0x80) to the message first 
            message->push_back(0x80); // 0x80 == 10000000

        		// append rest of (55 - remainder)bytes with (0x00)
            for (size_t i = 1; i < 56 - remainder; ++i)
            {
                message->push_back(0x00);
            }
        }

        //if remainder equals to 56 bytes = 448 bits
        else if (remainder == 56)
        {
            message->push_back(0x80);
            for (size_t i = 1; i < 64; ++i)
            {
                message->push_back(0x00);
            }
        }

    	
        //if remainder is greater than 56 bytes = 448 bits
        else
        {
			message->push_back(0x80);
            for (size_t i = 1; i < 64 - remainder + 56; ++i)
            {
                message->push_back(0x00);
            }
        }

    	
        //! append length of original text
        for (int i = 1; i <= 8; ++i)
        {
	        auto c = static_cast<uint8_t>(original_bit_size >> (64 - 8 * i));
            message->push_back(c);
        }

        return true;
    }

	
    return false;
       
}

bool Sha256::decomposeTextInto64BytesChunks(const std::vector<uint8_t>& message,
	std::vector<std::vector<uint8_t>>* chunks)
{

	//precondition if chunks exists and (size of message in bytes % 64 bytes) == 0  
	if(chunks && message.size() % 64 == 0)
	{
		
        chunks->clear(); // clear buffer first

        const size_t quotient = message.size() / 64;  //total quotient number of blocks
        for (size_t i = 0; i < quotient; ++i)
        {
            std::vector<uint8_t> temp(message.begin() + i * 64, message.begin() + (i + 1) * 64);
            chunks->push_back(temp);
        }
        return true;
    }
    
    // at this point, text message doesn't meet sha256 requirement, return false and not be hashed
    return false;
  
   
}

bool Sha256::constructWords(const std::vector<uint8_t>& chunk, std::vector<uint32_t>* words)
{
	if(words && chunk.size() == 64)
	{
        words->resize(64); //resize to 64 

        //for the first 16 words, i-th word is obtained by merging the chunk[4*i], chunk[4*i+1], chunk[4*i+2] and chunk[4*i+3] in big-endian format
		for(int i = 0; i < 16; i++)
		{
            (*words)[i] = static_cast<uint32_t>(chunk[4 * i] << 24) |
                          static_cast<uint32_t>(chunk[4 * i + 1] << 16) |
                          static_cast<uint32_t>(chunk[4 * i + 2] << 8) |
                          static_cast<uint32_t>(chunk[4 * i + 3]);
		}

		//from the rest 46 words(index from 16 to 63), using following iteration formula 
		for(int i = 16; i < 64; i++)
		{
			
            (*words)[i] = sigma_1((*words)[i - 2]) + (*words)[i - 7] + sigma_0((*words)[i - 15]) + (*words)[i - 16];
			
		}

        return true;

		
	}

	
    return false;
}


//message
bool Sha256::transform(const std::vector<uint32_t>& words, std::vector<uint32_t>* message_digest)
{
	if(message_digest && message_digest->size() == 8 && words.size() == 64)
	{
        uint32_t temp1{}, temp2{};
		
        std::vector<uint32_t> temp = *message_digest;

		// main loop: for every iteration i, each element in the message digest is
		// A' = H + Sigma_1(E) + Ch(E, F, G) + Words[i] + K[i] + Ma(A, B, C) + Sigma_0(A)
		// B' = A
		// C' = B
		// D' = C
		// E' = D + H + Sigma_1(E) + Ch(E, F, G) + Words[i] + K[i]
		// F' = E
		// G' = F
		// H' = G

		for(int i = 0; i<64; i++)
		{
            temp1 = temp[7] + Sigma_1(temp[4]) + Ch(temp[4], temp[5], temp[6]) + words[i] + K[i];
			temp2 = Sigma_0(temp[0]) + Ma(temp[0], temp[1], temp[2]);
			
            temp[7] = temp[6];
            temp[6] = temp[5];
            temp[5] = temp[4];
            temp[4] = temp[3] + temp1;
            temp[3] = temp[2];
            temp[2] = temp[1];
            temp[1] = temp[0];
            temp[0] = temp1 + temp2;
           
		}

		//last loop, add each element of message_digest by the final iterative value corresponding to the index of temp[i] 
		for(int i = 0; i<8; i++)
		{
            (*message_digest)[i] += temp[i];
		}

        return true;
		
	}

    return false;
	
}

bool Sha256::HashValue(const std::vector<uint32_t>& input, std::vector<uint8_t>* outHashVal)
{
	if(outHashVal)
	{
        outHashVal->clear();
		for(auto word: input)
		{
			for(int i = 0; i < 4; i++)
			{

				//split each word(32 bits) into 4 value with 8 bits each, push into outHashVal; 
                outHashVal->push_back(static_cast<uint8_t>(word) >> (24 - 8 * i));
			}
		}

        return true;
	}

    return false;
}

std::optional<std::string> Sha256::getHexEncryptedDigest(const std::string& message)
{
	if(message.empty())
	{
        return std::nullopt;
	}

    std::vector<uint8_t> original_message;
    original_message.reserve(message.size());

	for(auto character: message)
	//for(size_t i = 0; i < message.size(); i++)
	{
        original_message.push_back(static_cast<uint8_t>(character));
	}

	
    std::vector<uint8_t> encrypted_digest;
    encrypt(original_message, &encrypted_digest);

    std::ostringstream os;
    os << std::hex << std::setiosflags(std::ios::uppercase);
    for (auto it: encrypted_digest)
    {
        os << std::setw(2) << std::setfill('0')
            << static_cast<unsigned short>(it);
    }

    return os.str();

}

