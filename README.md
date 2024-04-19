# KExecDD
The Kernel Security Support Provider Interface (KSecDD.sys) allows the Local Security Authority Server Service (LSASS) to execute arbitrary kernel-mode addresses using the `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN` operation. This behavior can be observed in `ksecdd.sys!KsecIoctlHandleFunctionReturn`. As soon as LSASS starts, it invokes `lsass.exe!LsapOpenKsec` where it connects itself to the interface using the `IOCTL_KSEC_CONNECT_LSA` operation. From this point on, no further process can connect to the interface and therefore the logic can only be triggered by LSASS. Note, however, that exactly one connection can be created for each server silo, but I am not sure about the implications of this.

The proof of concept injects a DLL into the LSASS process from where it disables Driver Signature Enforcement by overwriting `ci.dll!g_CiOptions` (keep in mind that this will eventually trigger Patchguard after some time). This obviously only works if LSASS does not run as a protected process (LSA Protection has to be disabled).


# Demo
![](https://github.com/floesen/KExecDD/blob/main/demo.gif)
