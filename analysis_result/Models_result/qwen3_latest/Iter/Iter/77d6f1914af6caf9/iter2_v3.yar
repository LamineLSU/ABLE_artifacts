rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 03 E8 ?? ?? ?? ?? }  // JZ 0x3 followed by CALL
        $pattern1 = { 75 01 E8 ?? ?? ?? ?? }  // JNZ 0x1 followed by CALL
        $pattern2 = { 74 03 E8 53 40 FF FF }  // JZ 0x3 followed by specific CALL offset

    condition:
        any of them
}