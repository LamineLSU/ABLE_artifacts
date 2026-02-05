rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 C0 E8 ?? ?? ?? ?? }  // XOR+CALL (register zeroing)
        $pattern1 = { 33 C0 89 85 F0 FE FF FF }  // XOR+MOV (stack manipulation)
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? }  // PUSH+CALL (direct exit trigger)

    condition:
        any of them
}