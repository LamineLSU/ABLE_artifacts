rule MaliciousCodePattern
{
    meta:
        description = "Detects malicious code patterns involving multiple conditional jumps and function calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Cybersecurity Analyst"

    strings:
        $a = { 85 C0 74 14 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Test EAX, JE, push/pop, call
        $b = { 85 C0 74 0D E8 ?? ?? ?? ?? 85 C0 }                // Test EAX, JE, call
        $c = { 85 C0 74 0D E8 ?? ?? ?? ?? 8B 45 ?? }             // Test EAX, JE, call, mov

    condition:
        all of them
}