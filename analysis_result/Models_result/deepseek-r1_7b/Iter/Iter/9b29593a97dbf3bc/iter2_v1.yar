rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85C0 7412 ???? }  // TEST EAX + JE with wildcarded offset
        $pattern1 = { 6A5B 8BCE ???? }   // PUSH EBP + MOV with wildcarded displacement
        $pattern2 = { E8FF 85C0 ???? }    // CALL instruction with wildcarded offset
}