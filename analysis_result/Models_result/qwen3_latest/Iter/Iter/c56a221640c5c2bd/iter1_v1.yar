rule ExampleRule
{
    meta:
        author = "Your Name"
        description = "Example YARA rule with three patterns"
    
    strings:
        $pattern0 = { 8B 4D ?? 8B 4D ?? FFD0 }
        $pattern1 = { 50 8D B0 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? }
        $pattern2 = { 8B 4D ?? 50 FFD2 }
    
    condition:
        any of them
}