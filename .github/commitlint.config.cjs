module.exports = {
  extends: ["@commitlint/config-conventional"],
  plugins: [
    {
      rules: {
        "body-required-unless-chore": ({ body, type }) => [
          (type === "chore" || type === "docs") || Boolean(body),
          "commit body must not be empty unless the commit type is chore or docs",
        ],
      },
    },
  ],
  rules: {
    "body-required-unless-chore": [2, "always"],
  },
};
