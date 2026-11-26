'use strict';

const { BusinessRuleError } = require('../errors/AppError');

const isEnabled = () => {
    const value = process.env.FINANCIAL_EXECUTION_ENABLED;
    if (value === undefined || value === null || value === '') return process.env.NODE_ENV !== 'production';
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
};
const assertEnabled = (operation = 'Financial and supplier execution') => {
    if (!isEnabled()) throw new BusinessRuleError(`${operation} is temporarily disabled.`, 'EXECUTION_EMERGENCY_STOP');
};

module.exports = { isEnabled, assertEnabled };
