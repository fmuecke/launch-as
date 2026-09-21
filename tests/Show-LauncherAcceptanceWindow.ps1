# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
$form = [Windows.Forms.Form]::new()
$form.Text = 'launch-as Sandbox acceptance caller'
$form.Width = 480
$form.Height = 140
$form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
$label = [Windows.Forms.Label]::new()
$label.AutoSize = $true
$label.Text = 'Testing isolation from the standard caller window.'
$label.Left = 24
$label.Top = 30
$form.Controls.Add($label)
[Windows.Forms.Application]::Run($form)
