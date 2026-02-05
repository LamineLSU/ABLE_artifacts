rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Test EAX + JZ + Call to ExitProcess
        $pattern1 = { 50 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }        // Push EAX + Call to debugger check
        $pattern2 = { A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 }     // FS:[0x30] + MOV + SHR + TEST AL

    condition:
        any of them
}