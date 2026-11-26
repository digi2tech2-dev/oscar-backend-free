'use strict';

const express = require('express');
const authenticate = require('../../shared/middlewares/authenticate');
const authorize = require('../../shared/middlewares/authorize');
const requirePermission = require('../../shared/middlewares/requirePermission');
const auditPrivilegedMutation = require('../../shared/middlewares/auditPrivilegedMutation');
const catchAsync = require('../../shared/utils/catchAsync');
const whatsappController = require('./whatsapp.controller');

const router = express.Router();

router.use(authenticate);
router.use(authorize('ADMIN', 'SUPERVISOR'));
router.use(requirePermission('MANAGE_SETTINGS'));
router.use(auditPrivilegedMutation);

router.get('/status', catchAsync(whatsappController.getStatus));
router.post('/reconnect', catchAsync(whatsappController.reconnect));
router.post('/reset', authorize('ADMIN'), catchAsync(whatsappController.reset));

module.exports = router;
