rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass rule targeting conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? 7F C0 } // Bypass TEST EAX JZ
        $pattern1 = { ?? ?? ?? ?? 83 C4 85 C0 0F 84 ?? ?? ?? ?? } // Bypass TEST EAX JNZ
        $pattern2 = { FF 15 2C 64 45 DC 8B 45 DC } // Direct call bypass

    condition:
        any of them
}