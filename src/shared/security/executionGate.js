'use strict';

const { BusinessRuleError } = require('../errors/AppError');

const isEnabled = () => String(process.env.FINANCIAL_EXECUTION_ENABLED ?? 'true').trim().toLowerCase() !== 'false';
const assertEnabled = (operation = 'Financial and supplier execution') => {
    if (!isEnabled()) throw new BusinessRuleError(`${operation} is temporarily disabled.`, 'EXECUTION_EMERGENCY_STOP');
};

module.exports = { isEnabled, assertEnabled };
