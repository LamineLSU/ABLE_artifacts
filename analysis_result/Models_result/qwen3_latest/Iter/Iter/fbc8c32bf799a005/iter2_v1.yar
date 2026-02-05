rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 97 00 00 00 75 DD }  // CMP EAX,0x97 + JNE (loop control)
        $pattern1 = { 85 C0 74 06 8B 45 FC }   // TEST EAX,EAX + JE + MOV (post-GetForegroundWindow check)
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 C0 }  // CALL to GetForegroundWindow + TEST EAX,EAX (conditional chain)

    condition:
        any of them
}