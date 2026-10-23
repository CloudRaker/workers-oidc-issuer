// Writes a token and a private JWK member across chunk boundaries, last line without a newline (close flush).
process.stdout.write("Authorization: Bearer " + "A".repeat(30));
setTimeout(() => {
  process.stdout.write("B".repeat(30) + "\n" + '{"kid":"k1","d":"' + "A".repeat(30));
  setTimeout(() => process.stdout.write("B".repeat(30) + '"}'), 50);
}, 50);
