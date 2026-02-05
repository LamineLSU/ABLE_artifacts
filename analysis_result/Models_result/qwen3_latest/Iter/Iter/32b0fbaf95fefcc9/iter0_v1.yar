rule ExitProcess_Stub
{
    meta:
        description = "Detects a stub that calls ExitProcess, possibly used in evasion techniques."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "CyberSecurityTeam"
        date = "2023-10-05"
        hash = "SHA256:1234567890abcdef1234567890abcdef"

    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // push ebp, mov ebp, push [ebp+08h], call ___crtCorExitProcess
        $b = { FF 75 08 E8 ?? ?? ?? ?? }           // push [ebp+08h], call ___crtCorExitProcess
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? }        // push [ebp+08h], call ExitProcess

    condition:
        (uint8($a) and uint8($b) and uint8($c)) or (uint8($a) and uint8($c)) or (uint8($b) and uint8($c))
}