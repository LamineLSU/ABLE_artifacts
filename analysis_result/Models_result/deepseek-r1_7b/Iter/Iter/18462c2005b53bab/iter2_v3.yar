rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 }  ; mov ebp, esp followed by push dword ptr [ebp+08h]
        $pattern1 = { E8 C8 FF FF ?? ?? } ; call instruction
        $pattern2 = { 59 ?? ?? }       ; pop ecx after a call

    condition:
        any of them
}