rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting key instructions"
        cape_options = "bp0=$pattern0,action0=skip,bp1=$pattern1,action1=skip,bp2=$pattern2,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 E8 C8 FF FF }  // mov instruction leading to call
        $pattern1 = { FF 75 08 E8 C8 F5 }   // push dword ptr before call (unique displacement)
        $pattern2 = { 55 8B E8 C8 F5 A8 }   // push ebp followed by mov esp, unique context
    condition:
        any of them
}