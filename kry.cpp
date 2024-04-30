/*Author: Andrej Smatana
  file: sha256.cpp
  Description: Implementation of SHA-256 hash function according to NIST FIPS 180-4
               The program also computes the MAC of a message and does a length extension attack
*/
#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>
#include <iomanip>

typedef struct Arguments {
  bool compute_hash;
  std::string to_sha256;
  bool mac;
  std::string key;
  bool verify;
  bool extension_attack;
  std::string mac_to_attack;
  int lenOfPw = 0;
  std::string toAppend;
} arguments_t;

/**parse the stdin content*/
std::string parse_stdin() {
  std::string input;
  std::string line;

  while (std::getline(std::cin, line)) {
      if (!input.empty()) {
          input += '\n';
      }
      input += line;
  }
  return input;
}

/** parses the args */
arguments_t argparse(int argc, char * argv[]) {
  arguments_t args{};

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " [-c (stdin)] [-s (stdin) -k <password>] [-v (stdin) -k <password> -m <mac_to_verify>] [-e (stdin) -n <len_of_password> -m <mac_to_attack> -a <appended_msg>]" << std::endl;
    std::cerr << "Note:\t(stdin) is the input message" << std::endl;

    exit(1);
  }

  struct option long_options[] = {
    {"chash", no_argument, 0, 'c'},
    {"message", no_argument, 0, 's'},
    {"key", required_argument, 0, 'k'},
    {"verify", no_argument, 0, 'v'},
    {"mac", required_argument, 0, 'm'},
    {"extension_attack", no_argument, 0, 'e'},
    {"append", required_argument, 0, 'a'},
    {"length", required_argument, 0, 'n'},
    {0, 0, 0, 0}
  };

  int opt;
  int option_index = 0;

  while ((opt = getopt_long(argc, argv, "csvek:m:a:n:", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'c':
        args.compute_hash = true;
        args.to_sha256 = parse_stdin();
        break;
      case 's':
        args.mac = true;
        args.to_sha256 = parse_stdin();
        break;
      case 'k':
        args.key = optarg;
        break;
      case 'v':
        args.to_sha256 = parse_stdin();
        args.verify = true;
        break;
      case 'm':
        args.mac_to_attack = optarg;
        break;
      case 'e':
        args.to_sha256 = parse_stdin();
        args.extension_attack = true;
        break;
      case 'a':
        args.toAppend = optarg;
        break;
      case 'n':
        args.lenOfPw = std::stoi(optarg);
        break;
    }
  } 

  return args;
}


// SHA-256 constants
// 64 constant words of 32 bits (4 bytes)
const uint32_t g_wordConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/** Initial hash values */
uint32_t initHash[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**pad the message NIST-FIPS 180-4 std
 * 
 * @param input - message to pad
 * 
 * @return padded message, multiple of 512 bits
*/
std::string padMessage(const std::string &input, std::size_t lengthToAdd = 0, std::size_t skip = 0) {
  std::string msg = input;

  // append the bit "1" to the msg
  msg += static_cast<char>(0x80);

  // append the bit "0" until the length of the message is 448 bits modulo 512
  while (((msg.size() + skip) * 8) % 512 != 448) {
    msg += static_cast<char>(0x00);
  }

  // append the length of the message as a 64-bit big-endian integer
  // https://www.eecis.udel.edu/~davis/cpeg222/AssemblyTutorial/Chapter-15/ass15_3.html
  uint64_t inputLen = input.size() * 8;

  if (lengthToAdd % 8 != 0) {
    lengthToAdd = ((lengthToAdd / 8) + 1) * 8;
  }

  inputLen += lengthToAdd;

  for (int i = 7; i >= 0; i--) {
    msg += static_cast<char>((inputLen >> (i * 8)) & 0xFF);
  }

  return msg;
}

/** just sets the v]] initial hashes based on the given hash (param mac)
 * 
 * @param mac - a hash unwrapped to 8 words (32bit)
*/
void setInitialHashValuesFromMac(const std::string &mac) {
  for (int i = 0; i < 8; i++) {
    std::stringstream ss;
    ss << std::hex << mac.substr(i * 8, 8);
    ss >> initHash[i];
  }
}

/**Parse the padded message into N 512-bits blocks - M^(1), M^(2), ..., M^(N)
 * 
 * @param msg - padded message, size should be multiple of 512 bits (64B)
 * 
 * @return vector of 512-bit chunks (message has 512bits, hash is of 256bits)
*/
std::vector<std::string> parseMessage(const std::string &msg) {
  std::vector<std::string> chunks;

  for (std::size_t i = 0; i < msg.size(); i += 64) {
    chunks.push_back(msg.substr(i, 64));
  }

  return chunks;
}

/**prepares a msg schedule of 64 32-bit words*/
std::vector<uint32_t> prepareMessageSchedule(const std::string &chunk) {
  std::vector <uint32_t> messageSchedule(64);

  for (int i = 0; i < 16; i++) {
    messageSchedule[i] = 0;
    for (int j = 0; j < 4; j++) {
      messageSchedule[i] |= (static_cast<uint8_t>(chunk[i * 4 + j]) << (24 - j * 8));
    }
  }

  return messageSchedule;
}

void printExtendedMessage(const std::string &original, const std::size_t lenOfPw, const std::string &toAppend) {
  std::string padded = padMessage(original, lenOfPw * 8, lenOfPw);
  for (std::size_t i = 0; i < padded.size() - 8; i++) {
    if (std::isprint(padded[i])) {
      std::cout << padded[i];
    } else {
      printf("\\x%02x", static_cast<uint8_t>(padded[i]));
    }
  }

  std::string last8chars = padded.substr(padded.size() - 8);
  uint64_t last64bits = 0;
  for (int i = 0; i < 8; i++) {
    last64bits <<= 8;
    last64bits |= static_cast<uint8_t>(last8chars[i]);

    printf("\\x%02x", static_cast<uint8_t>(last8chars[i]));
  }

  std::cout << toAppend;
  std::cout << std::endl;
}


/**does a right rotation of the value by shift bits
 * so f.e. 
 *  right shift: 0b1110_1000 >> 3 = 0b0001_1101
 *  left shift: 0b1110_1000 << (8-3) = 0b0000_0000
 *  OR: 0b0000_0001 | 0b0001_1101 = 0b0001_1101
 * 
*/
uint32_t rightrotate(uint32_t value, int shift) {
  return (value >> shift) | (value << (32 - shift));
}

/** for readability*/
uint32_t rightshift(uint32_t value, int shift) {
  return value >> shift;
}

uint32_t calcS0(uint32_t value) {
  return rightrotate(value, 7) ^ rightrotate(value, 18) ^ rightshift(value, 3);
}

uint32_t calcS1(uint32_t value) {
  return rightrotate(value, 17) ^ rightrotate(value, 19) ^ rightshift(value, 10);
}

/** just compute sha256 with all the steps included (padding (512bit), parsing into 64 32-bit words, doing some rotations)*/
std::string sha256(const std::string &input, std::size_t lengthToAdd = 0) {
  // padding the input
  std::string msg = padMessage(input, lengthToAdd);

  // parse the message into 512-bit chunks
  std::vector <std::string> chunks = parseMessage(msg);

  for (std::string chunk: chunks) {
    std::vector <uint32_t> messageSchedule = prepareMessageSchedule(chunk);

    // msg sched Wt
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = calcS0(messageSchedule[i - 15]);
      uint32_t s1 = calcS1(messageSchedule[i - 2]);

      messageSchedule[i] = messageSchedule[i - 16] + s0 + messageSchedule[i - 7] + s1;
    }

    // 2. initialize the working variables
    uint32_t a = initHash[0];
    uint32_t b = initHash[1];
    uint32_t c = initHash[2];
    uint32_t d = initHash[3];
    uint32_t e = initHash[4];
    uint32_t f = initHash[5];
    uint32_t g = initHash[6];
    uint32_t h = initHash[7];

    // 3.
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t temp1 = h + S1 + ch + g_wordConstants[i] + messageSchedule[i];
      uint32_t S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // 4. update the hash values
    initHash[0] += a;
    initHash[1] += b;
    initHash[2] += c;
    initHash[3] += d;
    initHash[4] += e;
    initHash[5] += f;
    initHash[6] += g;
    initHash[7] += h;
  }

  std::string hash;

  for (int i = 0; i < 8; i++) {
    for (int j = 3; j >= 0; j--) {
      char hex[3];
      sprintf(hex, "%02x", static_cast<int>(initHash[i] >> (j * 8)) & 0xFF);
      hash += hex;
    }
  }

  return hash;
}

/** simple SHA(password + message) function*/
std::string mac_sha256(const std::string& secret_key, const std::string& message) {
  return sha256(secret_key + message);
}

/** call mac_sha256() in order to compare the given MAC and the newly computed MAC from given pw + msg
 * 
 * @param secret_key the key to compute the MAC
 * @param message the message to compute the MAC
 * @param mac the MAC to compare
 * 
 * @return 0 if the MACs are the same, 1 otherwise
*/
int verify_mac(const std::string& secret_key, const std::string& message, const std::string& mac) {
  std::string computed_mac = mac_sha256(secret_key, message);
  return !(computed_mac == mac);
}


void extension_attack(const std::string& input, const std::string& mac_to_attack, const std::string& toAppend, int lenOfPw) {
  // pad Message
  // the input and string of password with lenOfPw bytes
  std::string pw(lenOfPw, 0x00);
  std::string toPad = input + pw;
  std::string padded = padMessage(toPad);

  int paddedLength = padded.size() * 8;

  // disassemble the MAC into 8 words and set them as new working vars
  setInitialHashValuesFromMac(mac_to_attack);
  std::cout << sha256(toAppend, paddedLength) << std::endl;

  printExtendedMessage(input, lenOfPw, toAppend);
}

int main(int argc, char * argv[]) {
  arguments_t args = argparse(argc, argv);

  if (args.compute_hash) {
    std::cout << sha256(args.to_sha256) << std::endl;
  } else if (args.mac) {
    if (args.key.empty()) {
      std::cerr << "Error: key is missing (-k)" << std::endl;
      exit(1);
    }
    std::cout << mac_sha256(args.key, args.to_sha256) << std::endl;
  } else if (args.verify) {
    if (args.key.empty()) {
      std::cerr << "Error: key to verify is missing (-k)" << std::endl;
      exit(1);
    } 

    if (args.mac_to_attack.empty()) {
      std::cerr << "Error: MAC to verify is missing (-m)" << std::endl;
      exit(1);
    }

    return verify_mac(args.key, args.to_sha256, args.mac_to_attack);
  } else if (args.extension_attack) {
    if (args.mac_to_attack.empty()) {
      std::cerr << "Error: MAC to attack is missing (-m)" << std::endl;
      exit(1);
    }
    if (args.toAppend.empty()) {
      std::cerr << "Error: message to append is missing (-a)" << std::endl;
      exit(1);
    }
    if (args.lenOfPw == 0) {
      std::cerr << "Error: length of the password is missing" << std::endl;
      exit(1);
    }

    extension_attack(args.to_sha256, args.mac_to_attack, args.toAppend, args.lenOfPw);
  }

}