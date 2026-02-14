import { wallet, transactions } from "./wallet.js";
import { transCounter } from "./wallet.js";

function verifyPin(inputPin) {
    return inputPin === wallet.pin;
}

export function addFunds(pin, amount) {
    if (!verifyPin(pin)) {
        console.log("Access Denied: Incorrect PIN");
        return;
    }

    if (amount <= 0) {
        console.log("Invalid Amount: Deposit must be positive");
        return;
    }

    wallet.balance += amount;
    transactions.push({
        transId: Date.now(),
        type: "Deposit",
        amount,
        timestamp: new Date()
    });

    console.log(`Deposit Successful: ₹${amount}`);
}

export function spendFunds(pin, amount) {
    if (!verifyPin(pin)) {
        console.log("Access Denied: Incorrect PIN");
        return;
    }

    if (amount <= 0) {
        console.log("Invalid Amount: Withdrawal must be positive");
        return;
    }

    if (amount > wallet.balance) {
        console.log("Transaction Declined: Insufficient Funds.");
        return;
    }

    wallet.balance -= amount;
    transactions.push({
        transId: Date.now(),
        type: "Withdraw",
        amount,
        timestamp: new Date()
    });

    console.log(`Withdrawal Successful: ₹${amount}`);
}