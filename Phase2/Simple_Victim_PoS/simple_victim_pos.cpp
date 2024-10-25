#include <iostream>
#include <vector>
#include <string>

using namespace std;

// Struct to represent credit card data
struct CreditCardInfo {
    string cardNumber;
};

int main() {
    vector<CreditCardInfo> cardData;

    // Simulate the POS system accepting input
    string cardNumber;

    cout << "Enter card number EX: 9514-0974-7503-1791  \n(format: ####-####-####-####): ";
    getline(cin, cardNumber);
    
    // Store card data in memory
    CreditCardInfo newCard = {cardNumber };
    cardData.push_back(newCard);

    // Simulate saving to a CSV (optional)
    cout << "Simulating data storage...\n";
    cout << "Card Number: " << newCard.cardNumber << endl;

    // Program continues to hold the card data in memory for testing the RAM scraper
    cout << "Card data stored in memory. You can now run the RAM scraper on this process." << endl;

    // Infinite loop to keep the program running for the scraper test
    while (true) {
        // Keeps the POS system "running"
    }

    return 0;
}
