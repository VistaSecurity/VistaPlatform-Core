# Classification from host inventory

A device agent's host inventory supplies operating-system, vendor, model and exposed-port evidence to the classification catalogue. The supplied rules recognize client Windows and macOS as computers and Windows Server as servers. A Linux or BSD distribution name alone does not establish the machine's role.

New assets receive a matching rule's class. Existing unclassified assets can receive a class from first-hand host evidence; the change is recorded in class history. A conflicting class for an already classified asset becomes an approval proposal. Human declarations and previously rejected proposals are preserved, and learned-model results always require review.

Hostnames replace empty or IP-address display labels. Existing names are retained. Operators can curate the operating-system rules in **Catalog → Classification rules**.
