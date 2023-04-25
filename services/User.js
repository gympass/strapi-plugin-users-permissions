'use strict';

/**
 * User.js service
 *
 * @description: A set of functions similar to controller's actions to avoid code duplication.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const { sanitizeEntity, getAbsoluteServerUrl } = require('strapi-utils');

function normalize (strArray) {
  const resultArray = [];
  if (strArray.length === 0) { return ''; }

  if (typeof strArray[0] !== 'string') {
    throw new TypeError('Url must be a string. Received ' + strArray[0]);
  }

  // If the first part is a plain protocol, we combine it with the next part.
  if (strArray[0].match(/^[^/:]+:\/*$/) && strArray.length > 1) {
    strArray[0] = strArray.shift() + strArray[0];
  }

  // There must be two or three slashes in the file protocol, two slashes in anything else.
  if (strArray[0].match(/^file:\/\/\//)) {
    strArray[0] = strArray[0].replace(/^([^/:]+):\/*/, '$1:///');
  } else {
    strArray[0] = strArray[0].replace(/^([^/:]+):\/*/, '$1://');
  }

  for (let i = 0; i < strArray.length; i++) {
    let component = strArray[i];

    if (typeof component !== 'string') {
      throw new TypeError('Url must be a string. Received ' + component);
    }

    if (component === '') { continue; }

    if (i > 0) {
      // Removing the starting slashes for each component but the first.
      component = component.replace(/^[\/]+/, '');
    }
    if (i < strArray.length - 1) {
      // Removing the ending slashes for each component but the last.
      component = component.replace(/[\/]+$/, '');
    } else {
      // For the last component we will combine multiple slashes to a single one.
      component = component.replace(/[\/]+$/, '/');
    }

    resultArray.push(component);

  }

  let str = resultArray.join('/');
  // Each input component is now separated by a single slash except the possible first plain protocol part.

  // remove trailing slash before parameters or hash
  str = str.replace(/\/(\?|&|#[^!])/g, '$1');

  // replace ? in parameters with &
  const parts = str.split('?');
  str = parts.shift() + (parts.length > 0 ? '?': '') + parts.join('&');

  return str;
}

function urlJoin(...args) {
  const parts = Array.from(Array.isArray(args[0]) ? args[0] : args);
  return normalize(parts);
}

module.exports = {
  /**
   * Promise to count users
   *
   * @return {Promise}
   */

  count(params) {
    return strapi.query('user', 'users-permissions').count(params);
  },

  /**
   * Promise to search count users
   *
   * @return {Promise}
   */

  countSearch(params) {
    return strapi.query('user', 'users-permissions').countSearch(params);
  },

  /**
   * Promise to add a/an user.
   * @return {Promise}
   */
  async add(values) {
    if (values.password) {
      values.password = await strapi.plugins['users-permissions'].services.user.hashPassword(
        values
      );
    }

    return strapi.query('user', 'users-permissions').create(values);
  },

  /**
   * Promise to edit a/an user.
   * @return {Promise}
   */
  async edit(params, values) {
    if (values.password) {
      values.password = await strapi.plugins['users-permissions'].services.user.hashPassword(
        values
      );
    }

    return strapi.query('user', 'users-permissions').update(params, values);
  },

  /**
   * Promise to fetch a/an user.
   * @return {Promise}
   */
  fetch(params, populate) {
    return strapi.query('user', 'users-permissions').findOne(params, populate);
  },

  /**
   * Promise to fetch authenticated user.
   * @return {Promise}
   */
  fetchAuthenticatedUser(id) {
    return strapi.query('user', 'users-permissions').findOne({ id }, ['role']);
  },

  /**
   * Promise to fetch all users.
   * @return {Promise}
   */
  fetchAll(params, populate) {
    return strapi.query('user', 'users-permissions').find(params, populate);
  },

  hashPassword(user = {}) {
    return new Promise((resolve, reject) => {
      if (!user.password || this.isHashed(user.password)) {
        resolve(null);
      } else {
        bcrypt.hash(`${user.password}`, 10, (err, hash) => {
          if (err) {
            return reject(err);
          }
          resolve(hash);
        });
      }
    });
  },

  isHashed(password) {
    if (typeof password !== 'string' || !password) {
      return false;
    }

    return password.split('$').length === 4;
  },

  /**
   * Promise to remove a/an user.
   * @return {Promise}
   */
  async remove(params) {
    return strapi.query('user', 'users-permissions').delete(params);
  },

  async removeAll(params) {
    return strapi.query('user', 'users-permissions').delete(params);
  },

  validatePassword(password, hash) {
    return bcrypt.compare(password, hash);
  },

  async sendConfirmationEmail(user) {
    const userPermissionService = strapi.plugins['users-permissions'].services.userspermissions;
    const pluginStore = await strapi.store({
      environment: '',
      type: 'plugin',
      name: 'users-permissions',
    });

    const settings = await pluginStore
      .get({ key: 'email' })
      .then(storeEmail => storeEmail['email_confirmation'].options);

    const userInfo = sanitizeEntity(user, {
      model: strapi.query('user', 'users-permissions').model,
    });

    const confirmationToken = crypto.randomBytes(20).toString('hex');

    await this.edit({ id: user.id }, { confirmationToken });

    try {
      settings.message = await userPermissionService.template(settings.message, {
        URL: urlJoin(getAbsoluteServerUrl(strapi.config), '/auth/email-confirmation'),
        SERVER_URL: getAbsoluteServerUrl(strapi.config),
        ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
        USER: userInfo,
        CODE: confirmationToken,
      });

      settings.object = await userPermissionService.template(settings.object, {
        USER: userInfo,
      });
    } catch {
      strapi.log.error(
        '[plugin::users-permissions.sendConfirmationEmail]: Failed to generate a template for "user confirmation email". Please make sure your email template is valid and does not contain invalid characters or patterns'
      );
      return;
    }

    // Send an email to the user.
    await strapi.plugins['email'].services.email.send({
      to: user.email,
      from:
        settings.from.email && settings.from.name
          ? `${settings.from.name} <${settings.from.email}>`
          : undefined,
      replyTo: settings.response_email,
      subject: settings.object,
      text: settings.message,
      html: settings.message,
    });
  },
};
