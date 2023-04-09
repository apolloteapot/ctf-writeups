FROM python:3.10

RUN useradd --system chal

WORKDIR /chal

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./

RUN chown -R root:root ./* && \
    chmod -R o-w ./*

EXPOSE 5000

USER chal
ENV CHAL_CORTEX_URL tcp://user:pass@cortex:27492
CMD ["hypercorn", "-b", "0.0.0.0:5000", "-w", "4", "--backlog", "5", "--access-logfile", "-", "--error-logfile", "-", "thunderstruck:app"]
