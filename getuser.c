#include <stdio.h>
#include <stdlib.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int main()
{
    oid target_oid[] = {1, 3, 6, 1, 4, 1, 89, 79, 17, 1, 1};
    size_t target_oid_len = OID_LENGTH(target_oid);

    init_snmp("snmpget");

    // SNMP
    netsnmp_session session, *ss;
    snmp_sess_init(&session);
    session.peername = strdup("172.16.100.46");
    session.version = SNMP_VERSION_2c;
    session.community = "public";
    session.community_len = strlen(session.community);

    // Sock
    SOCK_STARTUP;
    ss = snmp_open(&session);
    if (!ss)
    {
        snmp_perror("snmp_open");
        SOCK_CLEANUP;
        exit(1);
    }

    // Logic to collect information
    char usernames[100][255];   
    char passwords[100][255];   
    long privilege_levels[100];

    int userCount = 0, passCount = 0, privCount = 0;

    netsnmp_pdu *response;
    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = 50;
    snmp_add_null_var(pdu, target_oid, target_oid_len);

    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response->variables)
    {
        for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable)
        {
            if (vars->name[10] == 4)
            {
                break;
            }

            if (vars->name[10] == 1)
            {
                snprintf(usernames[userCount], sizeof(usernames[userCount]), "%s", vars->val.string);
                userCount++;
            }

            if (vars->name[10] == 2)
            {
                snprintf(passwords[passCount], sizeof(passwords[passCount]), "%s", vars->val.string);
                passCount++;
            }

            if (vars->name[10] == 3)
            {
                privilege_levels[privCount] = *vars->val.integer;
                privCount++;
            }
        }
    }
    else
    {
        snmp_sess_perror("snmpget", ss);
    }

    // JSON   
    FILE *jsonFile = fopen("users.json", "w");
    if (jsonFile == NULL)
    {
        fprintf(stderr, "Error opening output.json for writing\n");
        exit(1);
    }

    // Printing in JSON file
    fprintf(jsonFile, "[\n");
    for (int i = 0; i < userCount; ++i)
    {
        fprintf(jsonFile, "  {\n");
        fprintf(jsonFile, "    \"username\": \"%s\",\n", usernames[i]);
        fprintf(jsonFile, "    \"password\": \"%s\",\n", passwords[i]);
        fprintf(jsonFile, "    \"privilege_level\": %ld\n", privilege_levels[i]);
        fprintf(jsonFile, "  }");
    fclose(jsonFile);
        if (i < userCount - 1)
        {
            fprintf(jsonFile, ",\n");
        }
    }
    fprintf(jsonFile, "\n]\n");


    fclose(jsonFile);
    snmp_close(ss);
    SOCK_CLEANUP;

    return 0;
}