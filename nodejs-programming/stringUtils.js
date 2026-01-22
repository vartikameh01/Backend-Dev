// 1. Capitalize function
function capitalize(str) {
  return str.toUpperCase();
}

// 2. Reverse string function
function reverseString(str) {
  return str.split("").reverse().join("");
}

// 3. Count vowels function
function countVowels(str) {
  let count = 0;
  let vowels = "aeiouAEIOU";

  for (let char of str) {
    if (vowels.includes(char)) {
      count++;
    }
  }
  return count;
}

// Export all functions
module.exports = {
  capitalize,
  reverseString,
  countVowels
};
