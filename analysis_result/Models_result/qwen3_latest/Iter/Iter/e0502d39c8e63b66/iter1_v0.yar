rule Targeted_Bypass
{
    meta:
        description = "Detects code segments leading to critical API calls in a specific binary"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI Analyst"
        date = "2023-10-05"
    strings:
        // Call to GetCommandLineA followed by AND operation
        $a = { FF 15 BC A0 41 00 83 65 E4 00 }
        // Call to GetStartupInfoA followed by indirect call
        $b = { FF 15 C0 A0 41 00 E8 47 00 00 00 }
        // Call to GetModuleHandleA followed by push ecx
        $c = { FF 15 44 A2 41 00 51 }
    condition:
        $a or $b or $c
}