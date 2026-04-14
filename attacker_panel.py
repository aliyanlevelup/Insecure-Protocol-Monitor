# Pentesters Dashboard: MITM Attacker Panel

class MITMAttacker:
    def __init__(self):
        self.network_logins = {}

    def perform_attack(self, target_ip):
        print(f'Performing MITM attack on {target_ip}')
        # Implement attack logic here

    def manage_login(self, username, password):
        print(f'Managing login for user: {username}')
        self.network_logins[username] = password

    def show_logins(self):
        print('Current logged in users:')
        for user in self.network_logins:
            print(user)

if __name__ == '__main__':
    attacker = MITMAttacker()
    attacker.manage_login('admin', 'password123')
    attacker.perform_attack('192.168.1.1')
    attacker.show_logins()