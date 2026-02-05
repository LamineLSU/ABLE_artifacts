rule Bypass_Sample_Evolved
{
    meta:
        description = "Detects sequences of instructions related to function calls and control flow in a memory trace."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 4B }  // Call to AllocConsole, test, je
        $pattern1 = { FF 15 40 30 FB 00 50 FF 15 BC 30 FB 00 }  // Call to GetStdHandle, push, call WriteConsoleW
        $pattern2 = { FF 15 A0 30 FB 00 FF 15 B4 30 FB 00 }  // Call to Sleep, call to FreeConsole

    condition:
        any of them
}