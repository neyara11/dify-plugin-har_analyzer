#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAR Analyzer Dify Plugin - Entry Point
"""

from dify_plugin import Plugin
from dify_plugin.config.config import DifyPluginEnv

plugin = Plugin(DifyPluginEnv())
plugin.run()
