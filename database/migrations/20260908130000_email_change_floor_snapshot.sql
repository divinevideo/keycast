-- Snapshot the suppression floor onto the email-change row.
--
-- The sync service needs to know, before subscribing a newly changed address, whether the person
-- had opted out of all email. It used to answer that by asking the email platform about the OLD
-- address.
--
-- That does not survive a second change. If somebody changes address twice before the drain runs,
-- the row says "B -> C" while the platform no longer knows B, so the lookup finds nothing, the floor
-- is invisible, and the sync subscribes a person who had asked not to be emailed.
--
-- Recording the answer at the moment of the change removes the reconstruction entirely: the value is
-- captured inside the same transaction that finalizes the change, when it is still known.
--
-- NULL means never observed, matching users.email_marketing_global_optout. A row written before this
-- column existed is also NULL, which is why the platform lookup remains as a fallback rather than
-- being deleted.
ALTER TABLE email_marketing_email_changes
    ADD COLUMN global_optout BOOLEAN;
