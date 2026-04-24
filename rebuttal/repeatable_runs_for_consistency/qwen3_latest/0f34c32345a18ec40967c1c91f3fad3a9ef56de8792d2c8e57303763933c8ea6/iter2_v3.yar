rule MalwareEvasion
{
    meta:
        description = "Detects evasion techniques in malware based on specific instruction sequences"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"

    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? }  // CMP EAX, EAX followed by JZ with offset
        $b = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 }  // CALL, ADD ESP, CMP EAX, EAX
        $c = { 6A ?? 5A E8 ?? ?? ?? ?? }  // PUSH, POP, CALL with offset

    condition:
        all of ($a, $b, $c)
}