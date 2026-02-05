rule ExampleRule
{
    meta:
        description = "Example YARA rule with three distinct patterns"
    
    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? } // Test EAX and JNE
        $b = { E8 ?? ?? ?? ?? 8B F8 50 83 F8 11 } // Call, MOV EDI, PUSH, CMP
        $c = { FF15 ?? ?? ?? ?? 58 5A 59 5B } // Call, POPs
    
    condition:
        all of them
}