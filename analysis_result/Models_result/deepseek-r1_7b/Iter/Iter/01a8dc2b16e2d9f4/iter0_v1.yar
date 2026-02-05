rule Bypass_Evasion_001 {
    meta:
        description = "Evasion bypass targeting TEST EAX with different JZ/JE paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? 74 07 } <!-- TEST EAX, JZ 0x05, JE 0x74 -->
        $pattern1 = { 85 C0 0F 84 ?? ?? 7D 0E } <!-- TEST EAX, JZ 0x08, JE 0x7D -->
        $pattern2 = { 85 C0 0F 84 ?? ?? 7E 0F } <!-- TEST EAX, JZ 0x0C, JE 0x7E -->

    condition:
        any of them
}