 \section{Opis kryptosystemów}
        \subsection{BGV (Brakerski–Gentry–Vaikuntanathan)}
        \label{sec:bgv}

            Kryptosystem BGV, nazwany od jego twórców – Zviki Brakerskiego, Craiga Gentry'ego i Vinoda Vaikuntanathana – to pierwszy zaawansowany schemat w pełni homomorficznego szyfrowania, opisany w 2011 roku w artykule \textit{Fully Homomorphic Encryption without Bootstrapping}~\cite{bgv_introduction}.

            U podstaw systemu BGV leży problem RLWE, który został opisany w Sekcji \ref{sec:rlwe}. Podstawowymi komponentami tego kryptosystemu są: generacja pary kluczy (prywatnego i publicznego), operacje szyfrowania wiadomości oraz deszyfrowania szyfrogramu z wykorzystaniem mechanizmów kontroli szumu oraz operacje homomorficzne, czyli operacje dodawania i mnożenia operujące na szyfrogramach wraz z algorytmami redukcji szumu oraz korekty błędów.

            \subsubsection{Inicjalizacja}

            Na samym początku inicjalizacji kryptosystemu, należy wybrać pierścień wielomianowy $R_q = \mathbb{Z}_q[X]/(X^n + 1)$, wewnątrz którego będą się odbywały wszystkie operacje związane z działaniem kryptosystemu. Oznacza to, że wszystkie elementy, takie jak szyfrogramy, klucze oraz inne parametry pomocnicze, będą elementami tego pierścienia.

            Pierścień $R_q$ jest definiowany przez dwie wartości: stopień $n$ wielomianu $X^n + 1$ oraz podstawę arytmetyki modularnej $q$, która powinna być dużą liczbą całkowitą.

            Kolejnym ważnym parametrem jest podstawa arytmetyki modularnej wiadomości, zwana $t$, która musi spełniać warunek $t << q$ i również być całkowita.

            Dodatkowo, do losowania szumu ($e, e_0, e_1$) używany jest dyskretny rozkład typu Gaussowskiego, np. wycentrowany rozkład dwumianowy, oznaczany jako $\chi$. Natomiast do wyliczania klucza prywatnego oraz podczas procesu szyfrowania (wielomian $u$) używany jest zawsze $\beta$-ograniczony rozkład dwumianowy.
    
            \subsubsection{Generowanie pary kluczy}

            Następnym etapem jest wygenerowanie pary kluczy: prywatnego oraz publicznego.
            
            Kryptosystem najpierw generuje klucz prywatny, którego generacja w najprostszej formie wygląda następująco:

            \begin{algorithm}[!htbp]
            \SetKwData{Left}{left}\SetKwData{This}{this}\SetKwData{Up}{up}
            \SetKwFunction{Union}{Union}\SetKwFunction{FindCompress}{FindCompress}
            \SetKwInOut{Input}{wejście}\SetKwInOut{Output}{wyjście}
            \Input{stopień wielomianu $n$}
            \Output{klucz prywatny $sk$}
            \BlankLine
            s <- wygeneruj losowy wielomian o rozmiarze $n$ z rozkładu dwumianowego\;
            sk <- s\;
            \textbf{return} sk\;
              \caption[BGV Generowanie klucza prywatnego]{BGV Generowanie klucza prywatnego}
              \label{alg:bgv-secret-key}
            \end{algorithm}

            Następnie generowany jest klucz publiczny zgodnie z Algorytmem \ref{alg:bgv-public-key}. Podczas tej operacji ważnym elementem jest ,,zaszumienie'' części \verb|pk_0| klucza publicznego poprzez losowo wygenerowany wielomian $e$.

            \begin{algorithm}[!htbp]
            \SetKwData{Left}{left}\SetKwData{This}{this}\SetKwData{Up}{up}
            \SetKwFunction{Union}{Union}\SetKwFunction{FindCompress}{FindCompress}
            \SetKwInOut{Input}{wejście}\SetKwInOut{Output}{wyjście}
            \Input{stopień wielomianu $n$, podstawa arytmetyki modularnej wiadomości $t$, klucz prywatny $sk$}
            \Output{klucz publiczny $(pk_0, pk_1)$}
            \BlankLine
            a <- wygeneruj losowy element (wielomian) z pierścienia $R_q$\;
            e <- wygeneruj niewielki (w sensie współczynników) wielomian z pierścienia $R_q$ przy pomocy dystrybucji $\chi$\;
            pk\_0 <- a * sk + t * e\;
            pk\_1 <- –1 * a\;
            \textbf{return (pk\_0, pk\_1)}\;
              \caption[BGV Generowanie klucza publicznego]{BGV Generowanie klucza publicznego}
              \label{alg:bgv-public-key}
            \end{algorithm}
            
            \subsubsection{Szyfrowanie wiadomości}

            Szyfrowanie wiadomości $m$ zostało przedstawione w postaci pseudokodu w Algorytmie \ref{alg:bgv-encrypt}.

            \begin{algorithm}[!htbp]
            \SetKwData{Left}{left}\SetKwData{This}{this}\SetKwData{Up}{up}
            \SetKwFunction{Union}{Union}\SetKwFunction{FindCompress}{FindCompress}
            \SetKwInOut{Input}{wejście}\SetKwInOut{Output}{wyjście}
            \Input{wiadomość $m$, klucz publiczny $pk$, podstawa arytmetyki modularnej wiadomości $t$}
            \Output{szyfrogram $(c_0, c_1)$}
            \BlankLine
            e\_0, e\_1 <- wygeneruj dwa niewielkie (w sensie współczynników) wielomiany z pierścienia $R_q$ przy pomocy dystrybucji $\chi$\;
            u <- wygeneruj losowy wielomian o rozmiarze $n$ z rozkładu dwumianowego\;
            pk\_0, pk\_1 <- pk\;
            c\_0 <- pk\_0 * u + t * e\_0 + m\;
            c\_1 <- pk\_1 * u + t * e\_1\;
            \textbf{return (c\_0, c\_1)}\;
              \caption[BGV Szyfrowanie]{BGV Szyfrowanie}
              \label{alg:bgv-encrypt}
            \end{algorithm}

            Ważnym aspektem procesu szyfrowania jest fakt, że części szyfrogramu $(c_0, c_1)$ pozostają elementami w pierścieniu $R_q$.
    
            \subsubsection{Operacje homomorficzne}

                Kryptosystem BGV, będąc kryptosystemem w pełni homomorficznym, wspiera operacje dodawania oraz mnożenia szyfrogramów.

                Zakładamy, że mamy dwie pary szyfrogramów $(c_0, \; c_1)$ oraz $(c'_0, \; c'_1)$, które są zaszyfrowane tym samym kluczem.

                \textbf{Dodawanie}

                Szyfrogram sumy jest równy $c^{*} = (c^{*}_0, \; c^{*}_1)$, przy czym $c^{*}_0 = c_0 + c'_0$ oraz $c^{*}_1 = c_1 + c'_1$.

                Poprawność powyższego równania można dowieść poprzez podstawienie równań z procesów szyfrowania i deszyfrowania:
                $$
                c^{*}_0 = c_0 + c'_0
                $$
                $$
                c^{*}_0 = (pk_0 * u + t * e_0 + m) + (pk_0 * u' + t * e'_0 + m')
                $$
                $$
                c^{*}_0 = pk_0 * (u + u') + t * (e_0 + e'_0) + m + m'
                $$
                $$
                c^{*}_0 = (a * sk + t * e) * (u + u') + t * (e_0 + e'_0) + m + m'
                $$
                $$
                c^{*}_0 = (a * sk) * (u + u')+ (t * e) * (u + u') + t * (e_0 + e'_0) + m + m'
                $$ 
            
                \\
                $$
                c^{*}_1 = c_1 + c'_1
                $$
                $$
                c^{*}_1 = (pk_1 * u + t * e_1) + (pk_1 * u' + t * e'_1)
                $$
                $$
                c^{*}_1 = pk_1 * (u + u') + t * (e_1 + e'_1)
                $$
                $$
                c^{*}_1 = -1 * a * (u + u') + t * (e_1 + e'_1)
                $$

                I po poddaniu procesowi deszyfrowania:
                $$
                c^{*}_0 + c^{*}_1 * sk = ((a * sk) * (u + u')+ (t * e) * (u + u') + t * (e_0 + e'_0) + m + m') + (-1 * a * (u + u') + t * (e_1 + e'_1)) * sk
                $$
                $$
                c^{*}_0 + c^{*}_1 * sk = \cancel{a * sk * (u + u')} + (t * e) * (u + u') + t * (e_0 + e'_0) + m + m' \cancel{- a * sk * (u + u')} + t * (e_1 + e'_1) * sk
                $$
                $$
                c^{*}_0 + c^{*}_1 * sk = t * (e * (u + u') + (e_0 + e'_0) + sk * (e_1 + e'_1)) + m + m', 
                $$

                gdzie $t * (e * (u + u') + (e_0 + e'_0) + sk * (e_1 + e'_1))$ to błąd szyfrowania i deszyfrowania, który nie może spowodować przekroczenia $q$ przez współczynniki wielomianu $m^*$.

                W ostatnim kroku wykonujemy operację $mod \; t$, co daje nam $m^* = m + m' \; mod \; t$.

                Wynikowy szyfrogram $c^*$ jest obłożony większym szumem niż szyfrogramy $c$ oraz $c'$, ponieważ podczas operacji homomorficznych szum propaguje. Aby temu zapobiec, stosuje się dodatkowe mechanizmy kontroli szumu opisane w ogólności w Sekcji \ref{sec:noise-control-general}.

                \noindent
                \textbf{Mnożenie}

                Szyfrogram iloczynu nie jest już taki prosty jak sumy – $c^{*} = (c^{*}_0, \; c^{*}_1, \; c^{*}_2)$, przy czym $c^{*}_0 = c_0 * c'_0$, $c^{*}_1 = c_0 * c'_1 + c_1 * c'_0$ oraz $c^{*}_2 = c_1 * c'_1$. Dzieje się tak, ponieważ wykonujemy operacje:
                $$
                m * m' = (c_0 + c_1 * sk) * (c'_0 + c'_1 * sk) = (c_1 * c'_1) * sk^2 + (c_0 * c'_1 + c_1 * c'_0) * sk + c_0 * c'_0
                $$

                Podobnie jak w przypadku dodawania, podczas mnożenia również rośnie szum wynikowego szyfrogramu. Jednakże większym problemem jest zwiększenie ilości komponentów szyfrogramu o jeden dodatkowy i to jeszcze drugiego stopnia względem klucza prywatnego. Aby rozwiązać tę sytuację, należy zastosować mechanizm relinearyzacji.
                
                \textbf{Relinearyzacja}

                Intuicyjnie proces relinearyzacji ma sprawić, aby równanie kwadratowe $c^*_2 * sk^2 + c^*_1 * sk + c^*_0$ przekształcić do postaci $\hat{c}_0 + \hat{c}_1 * \hat{sk}$ dla nowego klucza $\hat{sk}$.

                Dla BGV, proces relinearyzaji nazywa się \textit{Key switching} i polega on na znalezieniu nowego klucza $\hat{sk}$ na bazie starego klucza i nowej reprezentacji szyfrogramu $c'$, aby zachodziła równość $\langle c', sk' \rangle = \langle c, sk \rangle \bmod q$.

                Relinearyzacja rozpoczyna się od wykonania dekompozycji składnika $c^*_2$ szyfrogramu, która polega rozkładzie wektora wielomianu z reprezentacji w $R^n_q$ na reprezentację w $R^n_2$. Dobór nowej reprezentacji wynika z faktu, że wszystkie współczynniki $c^*_2$ są mniejsze niż $q$. Intuicyjnie tę dekompozycję można opisać jako proces analogiczny do zamiany liczby z systemu dziesiętnego na binarny.

                Nasz komponent $c^*_2$ jest wektorem reprezentującym współczynniki wielomianu stopnia $n$, więc można go w ogólności zapisać w postaci wielomianu:
                $$
                c^{(i)}(x) = c[0]^{(i)} + c[1]^{(i)}x + \dots + c[n-1]^{(i)}x^{n-1}
                $$
                i następnie dokonać dekompozycji zgodnie z równaniem:
                $$
                c = \sum_{i=0}^{\lfloor\log_2 q\rfloor} 2^i \cdot c^{(i)} \pmod q
                $$

                Proces dekompozycji jest oznaczany jako $BitDecomp(x, q)$, gdzie $x$ to wektor wielomianu, a $q$ to podstawa arytmetyki modularnej.

                Drugim krokiem jest tak zwane \textit{generowanie wskazówek z klucza prywatnego}, które polega na przekształceniu wektora wielomianu reprezentującego klucz prywatny do postaci:
                $$
                sk \in R^n_q \rightarrow (sk, 2sk, \dots, 2^{\lfloor log \; q\rfloor}sk) \in R^{n \lfloor log \; q\rfloor}_q
                $$

                Proces ten jest oznaczany jako $Powersof2(x, q)$, gdzie $x$ to wektor wielomianu, a $q$ to podstawa arytmetyki modularnej.

                Generowanie wskazówek można również rozpisać w alternatywny sposób:
                
                Dla $j=0,...,\lfloor \log_2 q\rfloor+1$ z klucza prywatnego $sk$ generujemy:
                $$
                (ek_0^{(j)},ek_1^{(j)})=(a_jsk+te_j+2^jsk^2,-a_j),
                $$

                gdzie $a_j \in R_q$ są generowane losowo z rozkładu jednostajnego, a błędy $e_i \in R_q$ - losowo z dystrybucji $\chi$. Proces ten jest powieleniem generowania klucza publicznego.
                

                Łącząc ze sobą te dwa kroki:
                $$
                \langle BitDecomp(c', q), \; Powersof2(sk', q) \rangle = \langle c, sk \rangle \bmod q
                $$

                W ostatnim kroku należy wygenerować nowy szyfrogram $(\hat{c}_0,\hat{c}_1)$:
                $$
                \hat{c}_0=c_0^{\ast}+\sum_{j=0}^{\lfloor \log_2 q\rfloor+1}ek_0^{(j)}c_2^{\ast (j)}
                $$
                $$
                \hat{c}_1=c_1^{\ast}+\sum_{j=0}^{\lfloor \log_2 q\rfloor+1}ek_1^{(j)}c_2^{\ast (j)}
                $$

                W taki sposób stworzony szyfrogram $(\hat{c}_0,\hat{c}_1)$ po procesie deszyfrowania powinien być wynikiem mnożenia $m * m'$.

                Konsekwencją mnożenia szyfrogramów i relinearyzacji jest jednak duży wzrost szumu. Aby go zredukować, należy zastosować kontrolę błędów modulo \textit{modulus switching}, która została opisana w czwartym paragrafie Sekcji \ref{par:modulus-switching}.

            \subsubsection{Deszyfrowanie szyfrogramu}

            Algorytm \ref{alg:bgv-decrypt} przedstawia kroki, jakie należy wykonać, aby odszyfrować wiadomość.

            \begin{algorithm}[H]
            \SetKwData{Left}{left}\SetKwData{This}{this}\SetKwData{Up}{up}
            \SetKwFunction{Union}{Union}\SetKwFunction{FindCompress}{FindCompress}
            \SetKwInOut{Input}{wejście}\SetKwInOut{Output}{wyjście}
            \Input{szyfrogram $c$, klucz prywatny $sk$, podstawa arytmetyki modularnej $q$, podstawa arytmetyki modularnej wiadomości $t$}
            \Output{szyfrogram $(c_0, c_1)$}
            \BlankLine
            c\_0, c\_1 <- c\;
            m = (c\_0 + sk * c\_1) \% q \% t\;
            \textbf{return m}\;
              \caption[BGV Deszyfrowanie]{BGV Deszyfrowanie}
              \label{alg:bgv-decrypt}
            \end{algorithm}

            \textit{Operacja $mod \; q$ może być rozwiązana poprzez odpowiednią implementację reprezentacji elementów pierścienia $R_q$.}

            Proces deszyfracji jest poprawny, jeżeli szum, który jest dodawany do wiadomości podczas procesu szyfrowania, nie sprawi, że współczynniki wielomianu reprezentującego wiadomość przekroczą próg kongruencji $q$.
            
            
        \subsection{BFV (Brakerski–Fan–Vercauteren)}
        \label{sec:bfv}

        Kryptosystem BFV opisany w 2012 roku, którego autorami są Fan oraz Vercauteren~\cite{bfv_introduction} w bardzo dużym stopniu bazuje na ówczesnych pracach Brakerskiego. Kryptosystem ten również jest w pełni homomorficznym systemem drugiej generacji i duża część jego implementacji opiera się na opisanej już implementacji BGV w Sekcji \ref{sec:bgv}. Przejdziemy jednak krok po kroku przez implementację BFV, wyróżniając różnice w stosunku do BGV.

            \subsubsection{Inicjalizacja}

                Proces inicjalizacji niewiele różni się pomiędzy BGV a BFV. Znaczącą różnicą jest zmiana rozkładu, z którego będą wyznaczane klucz prywatny $sk$ oraz wielomian $u$. Autorzy zdecydowali się zastosować tutaj próbkowanie z pierścienia $R_2$. Dodatkowo, wprowadzony został również współczynnik skalujący $\Delta = \lfloor \frac{q}{t} \rfloor$, który będzie wykorzystywany podczas szyfrowania wiadomości.

            \subsubsection{Generowanie pary kluczy}

                Generowanie klucza prywatnego następuje z próbkowania pierścienia $R_2$, natomiast generowanie klucza publicznego jest co do zasady identyczne z Algorytmem \ref{alg:bgv-public-key} BGV z dokładnością do zmiany znaku pomiędzy komponentami $pk_0 = -(a \cdot sk + te), \; pk_1 = a$.

            \subsubsection{Tworzenie kluczy relinearyzacji}

                W kryptosystemie BFV, tworzenie kluczy relinearyzacji przebiega w taki sam sposób jak dla BGV, lecz krok ten został przez autorów dodatkowo wyróżniony już na etapie tworzenia kryptosystemu.

            \subsubsection{Szyfrowanie wiadomości}

                Proces szyfrowania jest bardzo zbliżony do szyfrowania BGV, a różnicami są: wyznaczenie wielomianu $u$ poprzez losowe próbkowanie z pierścienia $R_2$ oraz dodanie współczynnika skalującego $\Delta = \lfloor \frac{q}{t} \rfloor$ do pierwszego składnika szyfrogramu do przeskalowania tekstu jawnego. Szyfrowanie BFV przedstawia Algorytm \ref{alg:bfv-encrypt}.

                \begin{algorithm}[H]
                \SetKwData{Left}{left}\SetKwData{This}{this}\SetKwData{Up}{up}
                \SetKwFunction{Union}{Union}\SetKwFunction{FindCompress}{FindCompress}
                \SetKwInOut{Input}{wejście}\SetKwInOut{Output}{wyjście}
                \Input{wiadomość $m$, klucz publiczny $pk$, podstawa arytmetyki modularnej wiadomości $t$}
                \Output{szyfrogram $(c_0, c_1)$}
                \BlankLine
                e\_0, e\_1 <- wygeneruj dwa niewielkie (w sensie współczynników) wielomiany z pierścienia $R_q$ przy pomocy dystrybucji $\chi$\;
                u <- wygeneruj losowy wielomian z pierścienia $R_2$\;
                pk\_0, pk\_1 <- pk\;
                c\_0 <- pk\_0 * u + t * e\_0 + $\Delta$ * m\;
                c\_1 <- pk\_1 * u + t * e\_1\;
                \textbf{return (c\_0, c\_1)}\;
                  \caption[BFV Szyfrowanie]{BFV Szyfrowanie}
                  \label{alg:bfv-encrypt}
                \end{algorithm}
                

            \subsubsection{Operacje homomorficzne}

                Operacja dodawania w BFV jest identyczna jak w BGV, natomiast operacja mnożenia została rozbudowana o dodatkowy sposób relinearyzacji:

                Pierwszym, zaprezentowanym również w BGV, sposobem relinearyzacji jest dekompozycja składnika $c^*_2$ szyfrogramu, czyli współczynnika stojącego przy kwadracie klucza prywatnego $sk^2$. Dekompozycja ta przebiega w podobny sposób jak dla BGV, z tą różnicą, że nowa baza wektora współczynników wielomianu po dekompozycji nie jest ustalona na stałe na $2$, lecz może zostać zmieniona i jest reprezentowana jako parametr $T$ (który nie jest zależny od $t$). Oznacza to, że dekompozycja jest dana wzorem:
                $$
                \hat{c_2} = \sum_{i=0}^{\lfloor\log_T q\rfloor} T^i \cdot c^{(i)} \pmod q
                $$
                Następnie, klucz relinearyzacji jest tworzony zgodnie ze wzorem:
                $$
                rlk = \left( \left[ \left( -\langle \mathbf{a}_i, \mathbf{s} \rangle + e_i \right) + T^i \cdot \mathbf{s}^2 \right]_q, \mathbf{a}_i \right) \;;\; i \in [0..\lfloor\log_T q\rfloor]
                $$
                Przeliczone zostają również składniki szyfrogramu zgodnie z kluczem relinearyzacji:
                $$
                \hat{c}_0= \left[ c_0^{\ast}+\sum_{j=0}^{\lfloor \log_T q\rfloor+1}rlk[j][0]c_2^{\ast (j)} \right]_q
                $$
                $$
                \hat{c}_1= \left[ c_1^{\ast}+\sum_{j=0}^{\lfloor \log_T q\rfloor+1}rlk[j][1]c_2^{\ast (j)} \right]_q
                $$
                I wynikowy szyfrogram po tych operacjach wygląda następująco:
                $$
                \hat{c'_0} + \hat{c'_1} \cdot sk = \hat{c}_0 + \hat{c}_1 \cdot s + \hat{c_2} sk^2 - \sum_{i=0}^{\ell} \hat{c_2}^{(i)} \cdot e_i \pmod q.
                $$

                Drugim, nowym sposobem relinearyzacji jest technika podobna do przełączania modułów (\textit{modulus switching}), która rozwiązuje problem powiększonych składników błędu napotykanych przy bezpośrednim maskowaniu $sk^2$. W pierwszym sposobie relinearyzacji składnik błędu $e_i$ jest mnożony przez $\hat{c_2}$, losowy element z $R_q$, co prowadzi do dużego zwiększenia błędu i wprowadza bardzo duży szum.

                Ta rozwiązuje ten problem, dostarczając zmodyfikowaną wersję $sk^2$, która może pomieścić ten dodatkowy błąd. Zamiast działać modulo $q$, klucz relinearyzacji jest generowany modulo $p \cdot q$ dla pewnej liczby całkowitej $p$, która jest dodatkowym parametrem systemu:
                $$
                \mathbf{rlk} = \left( \left[ \left( - \mathbf{a} \cdot \mathbf{s} + e \right) + p \cdot \mathbf{s}^2 \right]_{p \cdot q}, \mathbf{a} \right) \;;\; \mathbf{a} \in R_{p \cdot q}
                $$
                przy czym $e$ <- $\chi' \; ; \; \chi' \neq \chi$ – rozkład $\chi'$ musi być starannie dobrany z uwagi na jego wariancję. Autorzy nie mówią, jaki dokładnie rozkład powinien zostać zastosowany, lecz podają wymagania, które nakładają na wariancję tego rozkładu: jeżeli $p \cdot q = q^k \; ; \; k > 0, \; k \in \mathbb{R}$ oraz $||\chi|| < B$, to $||\chi'|| = B_k > \alpha^{1 - \sqrt{k}} \cdot q^{k - \sqrt{k}} \cdot B^{\sqrt{k}} \; ; \; \alpha \simeq 3.758$, gdzie $B$ to baza kraty. % nie pytajcie mnie co tu się dzieje, nie mam bladego pojęcia XD

                Następnie, składniki szyfrogramu zostają przetworzone zgodnie ze wzorami:
                $$
                (\mathbf{c}_{2,0}, \mathbf{c}_{2,1}) = \left(\left(\left\lfloor\frac{\mathbf{c}_2 \cdot \mathbf{rlk}[0]}{p}\right\rfloor\right)_q, \left(\left\lfloor\frac{\mathbf{c}_2 \cdot \mathbf{rlk}[1]}{p}\right\rfloor\right)_q\right)
                $$
                $$
                \hat{c}_0= [\mathbf{c}^*_0 + \mathbf{c}_{2,0}]_q
                $$
                $$
                \hat{c}_1= [\mathbf{c}^*_1 + \mathbf{c}_{2,1}]_q
                $$

                \subsubsection{Deszyfrowanie szyfrogramu}

                Proces deszyfrowania szyfrogramu w kryptosystemie BFV jest identyczny z procesem deszyfrowania w kryptosystemie BGV przedstawionym w Algorytmie \ref{alg:bgv-decrypt}.