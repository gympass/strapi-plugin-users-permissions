'use strict';

const { trim } = require('lodash/fp');

const authorizedKeys = ['URL', 'CODE', 'USER', 'USER.email', 'USER.username', 'TOKEN'];

const createStrictInterpolationRegExp = (allowedVariableNames, flags) => {
  const oneOfVariables = allowedVariableNames.join('|');

  return new RegExp(`<%=\\s*(${oneOfVariables})\\s*%>`, flags);
};

const createLooseInterpolationRegExp = (flags) => new RegExp(/<%=([\s\S]+?)%>/, flags);

const invalidPatternsRegexes = [
  // Ignore "evaluation" patterns: <% ... %>
  /<%[^=]([\s\S]*?)%>/m,
  // Ignore basic string interpolations
  /\${([^{}]*)}/m,
];

const matchAll = (pattern, src) => {
  const matches = [];
  let match;

  const regexPatternWithGlobal = RegExp(pattern, 'g');
  while ((match = regexPatternWithGlobal.exec(src))) {
    const [, group] = match;

    matches.push(trim(group));
  }
  return matches;
};

const isValidEmailTemplate = template => {
  for (let reg of invalidPatternsRegexes) {
    if (reg.test(template)) {
      return false;
    }
  }

  const interpolation = {
    // Strict interpolation pattern to match only valid groups
    strict: createStrictInterpolationRegExp(authorizedKeys),
    // Weak interpolation pattern to match as many group as possible.
    loose: createLooseInterpolationRegExp(),
  };

  const strictMatches = matchAll(interpolation.strict, template);
  const looseMatches = matchAll(interpolation.loose, template);

  if (looseMatches.length > strictMatches.length) {
    return false;
  }

  return true;
};

module.exports = {
  isValidEmailTemplate,
};
