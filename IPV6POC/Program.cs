using System;
using System.Text.RegularExpressions;
using System.Net;
using System.Collections.Generic;

namespace IPV6POC
{
    class Program
    {

        static void Main()
        {

            string[] ipv6Addresses = {
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3::8a2e:0370:7334",
                "2001:0db8:85a3:0:0:8a2e:0370:7334/48",
                "2001:0db8:85a3:0::8a2e:0370:7334",
                "::1",
                "fe80::1",
                "fd00:3453:d2f3:6987::1743",
                "fe80::50f2:f789:4d83:4bbc%7",
                "fe80::3653:d2ff:fef3:6989%7",
                "ff06::c3",
                "1050:0:0:0:5:600:300c:326b",
                "1050:0000:0000:0000:0005:0600:300c:326b",
                "0:0:0:0:0:ffff:192.1.56.10",
                "2001::",
                "2001::1",
                "2001:0db8::",
                "2001:0db8::1",
                "::",
                "0:0:0:0:0:0:0:1",
                "2001:0db8:85a3:00000:0000:8a2e:0370:7334",
                "invalid_ipv6_address"
            };


            foreach (string item in ipv6Addresses)
            {
                bool validate = ValidateIPv6Part2(item);
                if (validate)
                {
                    Console.WriteLine("Valid");
                }
                else
                {
                    Console.WriteLine(string.Format("Not valid - {0}", item));
                }
            }
        }

        static bool ValidateIPv6(string ipAddress)
        {
            if (ipAddress == null)
            {
                return false;
            }

            IPAddress ipaddress;
            bool isValid = IPAddress.TryParse(ipAddress, out ipaddress);

            // Regular expression pattern for validating IPv6 addresses
            //string pattern = @"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$";
            //string compressedPattern = @"^(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$";
            //string linkLocalPattern = @"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})%[a-zA-Z0-9]+$";

            //bool matchTwo = Regex.IsMatch(ipAddress, compressedPattern);
            //bool matchOne = Regex.IsMatch(ipAddress, pattern);
            //bool matchThree = Regex.IsMatch(ipAddress, linkLocalPattern);


            return isValid && ipaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        static bool ValidateIPv6Part2(string ipAddress)
        {
            if (ipAddress.Equals("::") || ipAddress.Equals("::1"))
            {
                return true;
            }

            if (ipAddress.Contains("::") && (ipAddress.IndexOf("::") != ipAddress.LastIndexOf("::")))
            {
                return false;
            }

            string[] parts = ipAddress.Split(':');

            if (parts.Length < 3 || parts.Length > 8)
            {
                return false;
            }

            int partCounter = 0;

            foreach (string part in parts)
            {
                if (part.Equals(""))
                {
                    partCounter++;
                    continue;
                }

                if (part.Contains(".") && partCounter == parts.Length - 1)
                {
                    return ValidateIPv4(part);
                }

                if (part.Length < 1 || part.Length > 4)
                {
                    bool valid = false;
                    foreach (char c in part)
                    {
                        if (!IsHexDigit(c))
                        {
                            if (ipAddress.Contains("fe80::") || ipAddress.Contains("FE80::"))
                            {
                                if (c == '%' && partCounter == parts.Length - 1)
                                {
                                    partCounter++;
                                    valid = true;
                                    break;
                                }
                            }
                            if (c == '/' && partCounter == parts.Length - 1)
                            {
                                string[] p = part.Split('/');
                                if (p.Length == 2)
                                {
                                    try
                                    {
                                        int num = Int32.Parse(p[1]);
                                        valid = true;
                                        break;
                                    }
                                    catch (Exception ex)
                                    {
                                        return false;
                                    }
                                }
                            }
                            return false;
                        }
                    }
                    if (!valid)
                    {
                        return false; // Each part should be a hexadecimal with a length of 1 to 4 characters
                    }
                }
                partCounter++;
            }

            return true;
        }

        static bool IsHexDigit(char c)
        {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }

        static bool ValidateIPv4(string ipAddress)
        {
            string[] parts = ipAddress.Split('.');

            if (ipAddress.Contains(" "))
            {
                return false;
            }
            try
            {
                if (ipAddress.StartsWith(".") || ipAddress.EndsWith(".") || parts.Length != 4)
                {
                    return false;
                }

                foreach (string p in parts)
                {
                    int numVal = Int32.Parse(p);
                    if (numVal < 0 || numVal > 255)
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
