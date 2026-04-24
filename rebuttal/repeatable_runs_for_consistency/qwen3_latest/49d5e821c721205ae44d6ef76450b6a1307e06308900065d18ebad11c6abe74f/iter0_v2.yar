rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // PUSH EBX + CALL with address
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // PUSH [EBP+08h] + CALL with offset
        $pattern2 = { E8 0B 00 00 00 FF 15 ?? ?? ?? ?? }  // CALL with offset + CALL with address

    condition:
        any of them
}