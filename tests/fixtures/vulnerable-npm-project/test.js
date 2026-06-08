const _ = require("lodash");
const [major, minor, patch] = _.VERSION.split(".").map(Number);
const expectedFixtureVersion = major === 4 && (minor > 17 || (minor === 17 && patch >= 20));
if (!expectedFixtureVersion) {
  throw new Error("unexpected lodash version: " + _.VERSION);
}
console.log("test ok");
