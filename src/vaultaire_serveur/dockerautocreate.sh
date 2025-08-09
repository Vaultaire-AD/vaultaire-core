#!/bin/sh
#Create group

go run /opt/vaultaire_cli.go create -g "Finance_Group" finance.company.com
go run /opt/vaultaire_cli.go create -g "HR_Group" hr.company.com
go run /opt/vaultaire_cli.go create -g "IT_Group" it.company.com
go run /opt/vaultaire_cli.go create -g "IT_Group-Infra" infra.it.company.com
go run /opt/vaultaire_cli.go create -g "Marketing_Group" marketing.company.com
go run /opt/vaultaire_cli.go create -g "Legal_Group" legal.company.com

#Create user

go run /opt/vaultaire_cli.go create -u alice.feur company.com secret123 06/02/1992
go run /opt/vaultaire_cli.go create -u bob company.com strongpass 09/12/1988
go run /opt/vaultaire_cli.go create -u fiona company.com mypass321 08/07/1985
go run /opt/vaultaire_cli.go create -u julie company.com loginme 10/09/1994
go run /opt/vaultaire_cli.go create -u charlie company.com admin987 03/09/1995 charlie lachocolaterie
go run /opt/vaultaire_cli.go create -u diana company.com pass456 01/07/1990 
go run /opt/vaultaire_cli.go create -u eric company.com devpass99 30/01/1993 
go run /opt/vaultaire_cli.go create -u george company.com testme! 12/11/1997 
go run /opt/vaultaire_cli.go create -u hannah company.com ff 04/02/1991 
go run /opt/vaultaire_cli.go create -u isaac company.com vault123 05/03/1989 
go run /opt/vaultaire_cli.go create -u proxmox_ldap_account company.com secret123 06/01/2004 proxmox Account

#add user to group
go run /opt/vaultaire_cli.go add -u alice -g Finance_Group
go run /opt/vaultaire_cli.go add -u bob -g HR_Group
go run /opt/vaultaire_cli.go add -u fiona -g IT_Group
go run /opt/vaultaire_cli.go add -u julie -g Marketing_Group
go run /opt/vaultaire_cli.go add -u charlie -g Legal_Group
go run /opt/vaultaire_cli.go add -u diana -g Finance_Group
go run /opt/vaultaire_cli.go add -u eric -g IT_Group
go run /opt/vaultaire_cli.go add -u eric -g IT_Group-Infra
go run /opt/vaultaire_cli.go add -u george -g Marketing_Group
go run /opt/vaultaire_cli.go add -u hannah -g HR_Group
go run /opt/vaultaire_cli.go add -u isaac -g Legal_Group
go run /opt/vaultaire_cli.go add -u proxmox_ldap_account -g IT_Group


#Create perm user

go run /opt/vaultaire_cli.go create -p -u "LDAP_ReadOnly" Lecture_seule_LDAP
go run /opt/vaultaire_cli.go create -p -u "LDAP_AdvancedSearch" Recherche_avancée_LDAP
go run /opt/vaultaire_cli.go create -p -u "LDAP_WriteAccess" Ecriture_dans_LDAP
go run /opt/vaultaire_cli.go create -p -u "LDAP_AdminPanel" Accès_admin_LDAP
go run /opt/vaultaire_cli.go create -p -u "LDAP_Monitoring" Monitoring_et_logs_LDAP

#Add perm user to group
go run /opt/vaultaire_cli.go add -gu Finance_Group -p LDAP_ReadOnly
go run /opt/vaultaire_cli.go add -gu HR_Group -p LDAP_AdvancedSearch
go run /opt/vaultaire_cli.go add -gu IT_Group -p LDAP_WriteAccess
go run /opt/vaultaire_cli.go add -gu Marketing_Group -p LDAP_Monitoring
go run /opt/vaultaire_cli.go add -gu Legal_Group -p LDAP_AdminPanel


#Create perm client
go run /opt/vaultaire_cli.go create -p -c "Client_ReadOnly" not
go run /opt/vaultaire_cli.go create -p -c "Client_AdminAccess" yes
go run /opt/vaultaire_cli.go create -p -c "Client_AuditLogs" not
go run /opt/vaultaire_cli.go create -p -c "Client_WriteOnly" not
go run /opt/vaultaire_cli.go create -p -c "Client_FullAccess" yes

#Add perm client to group
go run /opt/vaultaire_cli.go add -gc Finance_Group -p Client_ReadOnly
go run /opt/vaultaire_cli.go add -gc HR_Group -p Client_AdminAccess
go run /opt/vaultaire_cli.go add -gc IT_Group -p Client_FullAccess
go run /opt/vaultaire_cli.go add -gc Marketing_Group -p Client_AuditLogs
go run /opt/vaultaire_cli.go add -gc Legal_Group -p Client_WriteOnly

#create GPO
go run /opt/vaultaire_cli.go create -gpo finance-env --cmd "export FINANCE_REPORT_PATH=/data/finance/reports; alias finreport='cat $FINANCE_REPORT_PATH/latest_report.txt'"
go run /opt/vaultaire_cli.go create -gpo finance-security --cmd "export HISTCONTROL=ignoreboth; alias lock='gnome-screensaver-command -l'"

go run /opt/vaultaire_cli.go create -gpo hr-calendar --cmd "alias calhr='curl -s https://company.com/api/hr/calendar | jq '.' '"
go run /opt/vaultaire_cli.go create -gpo hr-notify --cmd "export HR_NOTIFICATION_LEVEL=high; alias notifyhr='echo \"Check your HR notifications!\"'"

go run /opt/vaultaire_cli.go create -gpo it-docker --cmd "alias dclean='docker system prune -af --volumes'"
go run /opt/vaultaire_cli.go create -gpo it-monitoring --cmd "alias sysmon='top -c | head -20'"

go run /opt/vaultaire_cli.go create -gpo marketing-stats --cmd "alias mkstats='curl -s https://api.marketing.company.com/stats | jq '.' '"
go run /opt/vaultaire_cli.go create -gpo marketing-update --cmd "alias mkupdate='git -C /srv/marketing-website pull origin main && systemctl reload nginx'"

go run /opt/vaultaire_cli.go create -gpo legal-checklist --cmd "alias legaldoc='cat /srv/legal/checklist.md'"
go run /opt/vaultaire_cli.go create -gpo legal-report --cmd "alias legalreport='curl -s https://legal.company.com/api/reports/latest'"

go run /opt/vaultaire_cli.go add -gpo finance-env -p Finance_Group
go run /opt/vaultaire_cli.go add -gpo finance-security -p Finance_Group

go run /opt/vaultaire_cli.go add -gpo hr-calendar -p HR_Group
go run /opt/vaultaire_cli.go add -gpo hr-notify -p HR_Group

go run /opt/vaultaire_cli.go add -gpo it-docker -p IT_Group
go run /opt/vaultaire_cli.go add -gpo it-monitoring -p IT_Group

go run /opt/vaultaire_cli.go add -gpo marketing-stats -p Marketing_Group
go run /opt/vaultaire_cli.go add -gpo marketing-update -p Marketing_Group

go run /opt/vaultaire_cli.go add -gpo legal-checklist -p Legal_Group
go run /opt/vaultaire_cli.go add -gpo legal-report -p Legal_Group

go run /opt/vaultaire_cli.go update -pu LDAP_WriteAccess search yes

go run /opt/vaultaire_cli.go create -u keycloak.ldap company.com it4 07/06/2025
go run /opt/vaultaire_cli.go create -g ALL company.com
go run /opt/vaultaire_cli.go add -gu ALL -p LDAP_WriteAccess
#ldap://vaultaire-ad.vaultaire.svc.cluster.local
#ldap://vaultaire-ad.vaultaire.svc.cluster.local
#dc=it,dc=company,dc=com