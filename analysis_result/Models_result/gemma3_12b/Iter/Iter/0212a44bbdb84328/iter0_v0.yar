rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 8B 45 ?? }  // Push EBP + MOV EBP + Push [ebp+8] + Call + MOV
        $pattern1 = { 59 FF 75 08 FF 15 ?? ?? ?? ?? } // Pop ECX + Push [ebp+8] + Call
        $pattern2 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? } // MOV EDI + Push EBP + MOV EBP + Call

    condition:
        any of them
}