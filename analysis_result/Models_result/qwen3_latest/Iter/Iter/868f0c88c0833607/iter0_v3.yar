rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // PUSH EBX + CALL ExitProcess + JMP to skip exit
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }      // TEST EAX + JZ + MOV EAX to skip exit check
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? }      // TEST EAX + JZ + MOV EBP to skip exit check

    condition:
        any of them
}