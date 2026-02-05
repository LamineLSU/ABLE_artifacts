rule MaliciousActivity
{
    meta:
        description = "Detects suspicious function calls and prologue patterns indicative of malicious activity"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$prologue+0,action2=skip,count=0"

    strings:
        $call1 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push ebp+08h followed by call to ExitProcess
        $call2 = { FF 75 08 E8 ?? ?? ?? ?? }    // Push ebp+08h followed by call to ___crtCorExitProcess
        $prologue = { 55 8B EC FF 75 08 }      // Standard function prologue

    condition:
        any of ($call1, $call2, $prologue)
}