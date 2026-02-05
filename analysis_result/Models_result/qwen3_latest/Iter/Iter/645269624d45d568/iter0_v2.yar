rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 90 E8 ?? ?? ?? ?? }  // NOP + ExitProcess call
        $pattern1 = { 50 E8 ?? ?? ?? ?? }  // PUSH EAX + Call to 04DE0FD0h
        $pattern2 = { 8B EC E8 ?? ?? ?? ?? }  // MOV EBP, ESP + Call to 0078A302h

    condition:
        all of them
}