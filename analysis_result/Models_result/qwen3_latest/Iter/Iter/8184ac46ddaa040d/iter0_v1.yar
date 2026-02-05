rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push EBX + Call [addr] (TRACE //1)
        $pattern1 = { C1 E8 08 A8 01 75 ?? }  // SHR + TEST AL + JNE (TRACE //5)
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }  // PUSH [ebp+08h] + CALL [addr] (TRACE //3)

    condition:
        any of them
}