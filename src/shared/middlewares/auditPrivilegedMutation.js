'use strict';

const crypto = require('node:crypto');
const { createAuditLogOrThrow } = require('../../modules/audit/audit.service');
const { ADMIN_ACTIONS, ENTITY_TYPES } = require('../../modules/audit/audit.constants');
const catchAsync = require('../utils/catchAsync');

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const auditPrivilegedMutation = catchAsync(async (req, res, next) => {
    if (!MUTATING_METHODS.has(req.method) || !['ADMIN', 'SUPERVISOR'].includes(req.user?.role)) return next();
    const context = req.auditContext;
    if (!context?.actorId || !context?.actorRole) {
        return res.status(401).json({ success: false, code: 'AUDIT_CONTEXT_REQUIRED', message: 'Authenticated audit context is required.' });
    }

    const requestId = crypto.randomUUID();
    const route = String(req.originalUrl || req.path || '').split('?')[0].slice(0, 300);
    await createAuditLogOrThrow({
        actorId: context.actorId,
        actorRole: context.actorRole,
        action: ADMIN_ACTIONS.PRIVILEGED_MUTATION_ATTEMPTED,
        entityType: ENTITY_TYPES.SYSTEM,
        metadata: { requestId, method: req.method, route },
        ipAddress: context.ipAddress || null,
        userAgent: context.userAgent || null,
    });
    res.set('X-Audit-Request-Id', requestId);
    next();
});

module.exports = auditPrivilegedMutation;
