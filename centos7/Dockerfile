FROM centos:7

RUN curl -fsSL -O https://raw.githubusercontent.com/cloudspinx/centos7-vault-repositories/main/generate_base_repos.sh
RUN bash generate_base_repos.sh

RUN curl -fsSL -O https://raw.githubusercontent.com/cloudspinx/centos7-vault-repositories/main/enable_repos.sh
RUN yes | bash enable_repos.sh

RUN mkdir ~/repos_backup
RUN mv /etc/yum.repos.d/* ~/repos_backup
RUN cp -r centos7_repos/* /etc/yum.repos.d/

RUN yum install -y python3-pip

RUN mkdir /app
WORKDIR /app
# cryptography<37 since version 37 considers python3.6 deprecated (and centos7 uses python3.6)
RUN python3 -m venv .venv && source .venv/bin/activate && pip install --upgrade pip && pip install tqdm 'cryptography<37' pyinstaller