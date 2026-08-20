.. _additional_configuration:

=============================================
Additional Configuration
=============================================

In this chapter we will enumerate several recommendations so as to make your Guest virtual machine as stealthy and operational as it gets. Additionally, we intend to address some of the most common problems that may arise.

Windows Guest
=============

Windows Debloating
------------------
There exist some tools that automatically try to debloat your Windows instance. That is, uninstalling lots of pre-installed software and disabling intrusive features of Windows. The purpose of these tools is optimization, performance, security or all of these. In the context of CAPE, they're useful to reduce noise and the probability of malware not detonating. Examples of these tools are `Debloat-Windows-10 <https://github.com/W4RH4WK/Debloat-Windows-10>`_ or `BlackBird <https://www.getblackbird.net/>`_. You can find a larger list `here <https://github.com/RazviOverflow/Malware_Resources?tab=readme-ov-file#windows-debloating-performance-privacy-optimization>`_.

.. note::
	It is recommended to use any of these tools to disable as much noise as possible. Remember to create a snapshot before executing them.

Disable Microsoft Store
-----------------------

Sometimes the Microsoft Store opens up as soon as an analysis starts. In order to disable it, you can remove the environment variable ``%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`` from the user ``PATH``, as specified in `this issue (#1237) <https://github.com/kevoreilly/CAPEv2/issues/1237#issuecomment-1308208474>`_.

Reduce Overall Noise
--------------------

Sometimes disabling all Windows services (like UAC, defender, update, aero, firewall, etc...) is necessary in order to make the analysis as fluent as possible.
Make sure you check the `disable_win7noise.bat`_ (Windows 7) and `win10_disabler.ps1`_ (Windows 10/11) scripts out and use them to get rid of all unnecessary noise. These are just examples. Your VM may require a different configuration in order to reduce or delete any Windows noise.

Run ``win10_disabler.ps1`` from an elevated PowerShell prompt, then reboot and let the VM idle for a few minutes before taking the clean snapshot::

    powershell -ExecutionPolicy Bypass -File win10_disabler.ps1

It accepts two switches: ``-KeepEdge`` keeps Edge and WebView2 installed while still disabling their updater, and ``-KeepUserServices`` keeps the ``UnistackSvcGroup`` per-user services (Mail/People/notifications) running.

.. warning::
    Take a snapshot before running any debloating script. Also keep in mind that a guest with every Windows feature stripped is itself a weak sandbox indicator, so only disable what actually gets in your way.

.. _disable_win7noise.bat: https://github.com/kevoreilly/CAPEv2/blob/master/installer/disable_win7noise.bat
.. _win10_disabler.ps1: https://github.com/kevoreilly/CAPEv2/blob/master/installer/win10_disabler.ps1

Where the background processes come from
----------------------------------------

Removing Edge and the WebView2 Runtime is worth doing, but it only accounts for the ``MicrosoftEdgeUpdate.exe`` family. The rest of the processes you will see in an idle Windows 10 guest come from unrelated Windows features that have to be disabled separately. The table below maps what typically shows up in a behavioural report to the thing that has to be switched off.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Process in the report
     - What to disable
   * - ``MicrosoftEdgeUpdate.exe`` (``/svc``, ``/ping``, ``/regsvc``, ``/regserver``), ``MicrosoftEdgeUpdateSetup_*.exe``, ``MicrosoftEdgeUpdateComRegisterShell.exe``
     - Uninstall Edge and WebView2, disable the ``edgeupdate`` and ``edgeupdatem`` services and the ``MicrosoftEdgeUpdateTask*`` scheduled tasks, and set the ``EdgeUpdate`` update policies to 0
   * - ``MusNotification.exe``, ``MusNotificationUx.exe``, ``MoUsoCoreWorker.exe``, ``sc.exe start wuauserv``
     - ``wuauserv``, ``UsoSvc`` and ``WaaSMedicSvc`` services, plus the ``UpdateOrchestrator`` and ``WindowsUpdate`` task folders
   * - ``sc.exe start pushtoinstall registration``
     - ``PushToInstall`` service and the Store auto-update policy
   * - ``devicecensus.exe``, ``CompatTelRunner.exe``
     - ``DiagTrack`` service, ``AllowTelemetry=0``, and the ``Device Information`` and ``Application Experience`` task folders
   * - ``clipesu.exe``
     - ``\Microsoft\Windows\Clip\License Validation`` task
   * - ``svchost.exe -k WerSvcGroup``, ``WerFault.exe``
     - ``WerSvc`` service and the Windows Error Reporting policy
   * - ``svchost.exe -s WdiSystemHost`` / ``-s WdiServiceHost``
     - ``DPS`` (Diagnostic Policy Service), which starts both
   * - ``svchost.exe -s PcaSvc``
     - ``PcaSvc`` service and the ``AppCompat`` policies
   * - ``svchost.exe -s dmwappushservice`` / ``-s SmsRouter``
     - ``dmwappushservice`` and ``SmsRouter`` services
   * - ``svchost.exe -k UnistackSvcGroup``
     - ``CDPUserSvc``, ``OneSyncSvc``, ``UnistoreSvc``, ``UserDataSvc`` and friends, disabled on the service *template* key
   * - ``taskhostw.exe``
     - Generic task host, it goes away as the tasks above are disabled
   * - ``dllhost.exe /Processid:{...}``
     - A COM surrogate. Look the CLSID up under ``HKCR\CLSID\{...}`` to find the component that asked for it

A few notes on doing this reliably:

* ``WaaSMedicSvc`` exists specifically to undo changes to the update stack, so disable it in the same pass. It rejects ``sc config``; write ``Start=4`` to ``HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc`` instead.
* Most tasks under ``\Microsoft\Windows\UpdateOrchestrator\`` are owned by ``TrustedInstaller`` and refuse to be disabled even from an elevated prompt. Disabling ``UsoSvc`` covers them.
* The services in ``UnistackSvcGroup`` are per-user templates. The running instances are named ``<Template>_<luid>``, so they have to be disabled on the template key rather than on the instance.
* Automatic Maintenance is the idle trigger behind ``devicecensus.exe``, ``clipesu.exe`` and several others. Setting ``MaintenanceDisabled=1`` under ``HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance`` stops anything you missed from firing during an analysis.
* Do not disable ``DcomLaunch``, ``RpcSs`` or ``Schedule``. The guest agent and the analyzer need them.

Once the snapshot is rebuilt, verify from inside the VM that the guest really is quiet before saving it::

    Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Sort-Object Name

Windows automatically enables the Virus Real-time Protection
------------------------------------------------------------

One possible annoying behavior of Windows occurs when it automatically enables the real-time protection whenever an analysis is started therefore deleting the sample (if it identifies the sample as malware).

To definitely turn it off you can follow one or more options listed in `this site <https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.html>`_.
